export interface Env {
  TELEGRAM_BOT_TOKEN: string;
  FIREBASE_PROJECT_ID: string;
  FIREBASE_CLIENT_EMAIL: string;
  FIREBASE_PRIVATE_KEY: string; // PEM كامل، بالأسرار (secret) مو بالمتغيرات العادية
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

/// توكن وصول مؤقت (ساعة وحدة) للتعامل مع Firestore REST API
async function getAccessToken(env: Env): Promise<string> {
  const privateKey = await importPrivateKey(env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'));
  const now = Math.floor(Date.now() / 1000);

  const jwt = await signJwt(
    {
      iss: env.FIREBASE_CLIENT_EMAIL,
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
async function mintCustomToken(env: Env, uid: string): Promise<string> {
  const privateKey = await importPrivateKey(env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'));
  const now = Math.floor(Date.now() / 1000);

  return signJwt(
    {
      iss: env.FIREBASE_CLIENT_EMAIL,
      sub: env.FIREBASE_CLIENT_EMAIL,
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

async function getDoc(env: Env, token: string, path: string) {
  const res = await fetch(`${FIRESTORE_ROOT(env.FIREBASE_PROJECT_ID)}/${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  const data = (await res.json()) as any;
  return fsParse(data.fields);
}

async function patchDoc(
  env: Env,
  token: string,
  path: string,
  fields: Record<string, unknown>
) {
  const updateMask = Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join('&');
  await fetch(`${FIRESTORE_ROOT(env.FIREBASE_PROJECT_ID)}/${path}?${updateMask}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, fsValue(v)])),
    }),
  });
}

async function deleteDoc(env: Env, token: string, path: string) {
  await fetch(`${FIRESTORE_ROOT(env.FIREBASE_PROJECT_ID)}/${path}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
}

async function findUidByPhone(env: Env, token: string, phone: string): Promise<string | null> {
  const res = await fetch(`${FIRESTORE_ROOT(env.FIREBASE_PROJECT_ID)}:runQuery`, {
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

// ============ Telegram helper ============

async function sendTelegramMessage(
  env: Env,
  chatId: number,
  text: string,
  replyMarkup?: Record<string, unknown>
) {
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, reply_markup: replyMarkup }),
  });
}

// ============ منطق التحقق الأساسي ============

async function verifyAndMatch(env: Env, token: string, phone: string, code: string): Promise<boolean> {
  const data = await getDoc(env, token, `phone_verifications/${phone}`);
  if (!data) return false;
  if (data.status !== 'pending') return false;
  if (data.code !== code) return false;

  if (data.expiresAt instanceof Date && new Date() > data.expiresAt) {
    await patchDoc(env, token, `phone_verifications/${phone}`, { status: 'expired' });
    return false;
  }

  let uid = await findUidByPhone(env, token, data.phone as string);
  if (!uid) uid = crypto.randomUUID();

  const customToken = await mintCustomToken(env, uid);

  await patchDoc(env, token, `phone_verifications/${phone}`, {
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

    try {
      const update = (await request.json()) as any;
      const message = update.message;
      if (!message) return new Response('OK');

      const chatId: number = message.chat.id;
      const accessToken = await getAccessToken(env);

      // الحالة 1: /start يحتوي الكود
      if (typeof message.text === 'string' && message.text.startsWith('/start')) {
        const code = message.text.split(' ')[1];

        if (code && /^\d{6}$/.test(code)) {
          await patchDoc(env, accessToken, `telegram_sessions/${chatId}`, { code });
          await sendTelegramMessage(
            env,
            chatId,
            'لإتمام التوثيق، شارك رقم هاتفك بالضغط على الزر بالأسفل 👇',
            {
              keyboard: [[{ text: '📱 مشاركة رقم الهاتف', request_contact: true }]],
              resize_keyboard: true,
              one_time_keyboard: true,
            }
          );
        } else {
          await sendTelegramMessage(env, chatId, 'رابط التوثيق غير صالح، الرجاء إعادة المحاولة من التطبيق.');
        }
        return new Response('OK');
      }

      // الحالة 2: مشاركة رقم الهاتف
      if (message.contact) {
        const session = await getDoc(env, accessToken, `telegram_sessions/${chatId}`);
        if (!session) {
          await sendTelegramMessage(env, chatId, 'انتهت الجلسة، الرجاء البدء من جديد من التطبيق.');
          return new Response('OK');
        }

        const phone = String(message.contact.phone_number).replace('+', '').trim();
        const success = await verifyAndMatch(env, accessToken, phone, session.code as string);

        await sendTelegramMessage(
          env,
          chatId,
          success ? '✅ تم التوثيق بنجاح، ارجع للتطبيق.' : '❌ الكود غير صحيح أو منتهي، حاول من جديد.'
        );

        await deleteDoc(env, accessToken, `telegram_sessions/${chatId}`);
        return new Response('OK');
      }

      return new Response('OK');
    } catch (err) {
      console.error('Telegram webhook error:', err);
      return new Response('OK'); // دايمًا 200 حتى لو صار خطأ، وإلا تيلجرام يعيد المحاولة بإزعاج
    }
  },
};
