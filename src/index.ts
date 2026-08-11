export interface Env {
  TELEGRAM_BOT_TOKEN: string;
  FIREBASE_SERVICE_ACCOUNT: string; // ملف الـ JSON كامل، بالأسرار (secret)
}

interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
}

const FIRESTORE_ROOT = (projectId: string) =>
  `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;

// ============ JWT signing عبر Web Crypto (بديل firebase-admin) ============

function base64url(input: ArrayBuffer | string): string {
  const bytes =
    typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const cleaned = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(pem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function signJwt(payload: Record<string, unknown>, privateKey: CryptoKey): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT' };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${base64url(signature)}`;
}

function parseServiceAccount(env: Env): ServiceAccount {
  const raw = (env.FIREBASE_SERVICE_ACCOUNT || '').replace(/^\uFEFF/, '').trim();
  const sa = JSON.parse(raw) as ServiceAccount;
  if (!sa.private_key || !sa.client_email || !sa.project_id) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT ناقص حقول أساسية (private_key/client_email/project_id)');
  }
  return sa;
}

/// توكن وصول مؤقت (ساعة وحدة) للتعامل مع Firestore REST API
async function getAccessToken(sa: ServiceAccount): Promise<string> {
  const privateKey = await importPrivateKey(sa.private_key);
  const now = Math.floor(Date.now() / 1000);

  const jwt = await signJwt(
    {
      iss: sa.client_email,
      scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    },
    privateKey
  );

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const data = (await res.json()) as { access_token?: string; error?: string };
  if (!data.access_token) throw new Error(`OAuth token failed: ${JSON.stringify(data)}`);
  return data.access_token;
}

/// Custom Token لتسجيل الدخول بالتطبيق — موقّع محليًا، بدون أي طلب شبكة
async function mintCustomToken(sa: ServiceAccount, uid: string): Promise<string> {
  const privateKey = await importPrivateKey(sa.private_key);
  const now = Math.floor(Date.now() / 1000);

  return signJwt(
    {
      iss: sa.client_email,
      sub: sa.client_email,
      aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
      iat: now,
      exp: now + 3600,
      uid,
    },
    privateKey
  );
}

// ============ Firestore REST helpers ============

function fsValue(v: unknown): Record<string, unknown> {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return { integerValue: String(v) };
  throw new Error('Unsupported value type for Firestore write');
}

function fsParse(fields: Record<string, any> = {}): Record<string, any> {
  const out: Record<string, any> = {};
  for (const key in fields) {
    const val = fields[key];
    if ('stringValue' in val) out[key] = val.stringValue;
    else if ('booleanValue' in val) out[key] = val.booleanValue;
    else if ('integerValue' in val) out[key] = Number(val.integerValue);
    else if ('timestampValue' in val) out[key] = new Date(val.timestampValue);
    else if ('nullValue' in val) out[key] = null;
  }
  return out;
}

async function patchDoc(
  projectId: string,
  token: string,
  path: string,
  fields: Record<string, unknown>
) {
  const updateMask = Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join('&');
  await fetch(`${FIRESTORE_ROOT(projectId)}/${path}?${updateMask}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, fsValue(v)])),
    }),
  });
}

async function findUidByPhone(projectId: string, token: string, phone: string): Promise<string | null> {
  const res = await fetch(`${FIRESTORE_ROOT(projectId)}:runQuery`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: 'users' }],
        where: {
          fieldFilter: {
            field: { fieldPath: 'phone' },
            op: 'EQUAL',
            value: { stringValue: phone },
          },
        },
        limit: 1,
      },
    }),
  });
  const rows = (await res.json()) as Array<{ document?: { name: string } }>;
  const doc = rows.find((r) => r.document)?.document;
  if (!doc) return null;
  return doc.name.split('/').pop() ?? null;
}

/// يدور على طلب تحقق pending يطابق نفس الكود المرسل من تيلجرام (بأي كولكشن phone_verifications)
async function findPendingByCode(
  projectId: string,
  token: string,
  code: string
): Promise<{ phone: string; fields: Record<string, any> } | null> {
  const res = await fetch(`${FIRESTORE_ROOT(projectId)}:runQuery`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: 'phone_verifications' }],
        where: {
          compositeFilter: {
            op: 'AND',
            filters: [
              {
                fieldFilter: {
                  field: { fieldPath: 'code' },
                  op: 'EQUAL',
                  value: { stringValue: code },
                },
              },
              {
                fieldFilter: {
                  field: { fieldPath: 'status' },
                  op: 'EQUAL',
                  value: { stringValue: 'pending' },
                },
              },
            ],
          },
        },
        limit: 1,
      },
    }),
  });
  const rows = (await res.json()) as Array<{ document?: { name: string; fields: any } }>;
  const doc = rows.find((r) => r.document)?.document;
  if (!doc) return null;
  const phone = doc.name.split('/').pop() ?? '';
  return { phone, fields: fsParse(doc.fields) };
}

// ============ Telegram helper ============

async function sendTelegramMessage(env: Env, chatId: number, text: string) {
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text }),
  });
}

// ============ منطق التحقق الأساسي ============

async function verifyByCode(sa: ServiceAccount, token: string, code: string): Promise<boolean> {
  const found = await findPendingByCode(sa.project_id, token, code);
  if (!found) return false;

  const { phone, fields } = found;

  if (fields.expiresAt instanceof Date && new Date() > fields.expiresAt) {
    await patchDoc(sa.project_id, token, `phone_verifications/${phone}`, { status: 'expired' });
    return false;
  }

  let uid = await findUidByPhone(sa.project_id, token, fields.phone as string);
  if (!uid) uid = crypto.randomUUID();

  const customToken = await mintCustomToken(sa, uid);

  await patchDoc(sa.project_id, token, `phone_verifications/${phone}`, {
    status: 'verified',
    uid,
    customToken,
  });

  return true;
}

// ============ نقطة الدخول ============

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== '/telegram-webhook' || request.method !== 'POST') {
      return new Response('OK');
    }

    let sa: ServiceAccount;
    try {
      sa = parseServiceAccount(env);
    } catch (err) {
      console.error('Telegram webhook error: bad service account —', err instanceof Error ? err.message : String(err));
      return new Response('OK');
    }

    try {
      const update = (await request.json()) as any;
      const message = update.message;
      if (!message || typeof message.text !== 'string') return new Response('OK');

      const chatId: number = message.chat.id;
      const text: string = message.text.trim();

      // نتجاهل /start (ترحيبي بس)، ونعالج أي رسالة نصية باقية كأنها كود محتمل
      if (text.startsWith('/start')) {
        await sendTelegramMessage(env, chatId, 'أرسل رمز التوثيق المكوّن من 6 أرقام الظاهر بالتطبيق.');
        return new Response('OK');
      }

      if (!/^\d{6}$/.test(text)) {
        return new Response('OK');
      }

      const accessToken = await getAccessToken(sa);
      const success = await verifyByCode(sa, accessToken, text);

      await sendTelegramMessage(
        env,
        chatId,
        success ? '✅ تم التوثيق بنجاح، ارجع للتطبيق.' : '❌ الكود غير صحيح أو منتهي، حاول من جديد.'
      );

      return new Response('OK');
    } catch (err) {
      console.error('Telegram webhook error:', err instanceof Error ? err.message : String(err));
      return new Response('OK'); // دايمًا 200 حتى لو صار خطأ، وإلا تيلجرام يعيد المحاولة بإزعاج
    }
  },
};
