// AES and RSA helpers for Cloudflare Worker (TypeScript)
// - AES-CTR with 12-byte IV prepended to ciphertext. Returned format: 'ENC:' + base64(iv||ciphertext)
// - Symmetric key is 16 bytes (128-bit) encoded as base64 when passed around. RSA-OAEP (SHA-256) used to encrypt the symmetric key with client's public key (SPKI PEM).

export function genRandomKeyBase64(): string {
  const u8 = crypto.getRandomValues(new Uint8Array(16));
  return uint8ToBase64(u8);
}

export async function encryptString(plain: string, keyBase64: string): Promise<string> {
  if (!keyBase64) throw new Error('missing key');
  const keyBytes = base64ToUint8(keyBase64);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-CTR', false, ['encrypt']);
  const iv12 = crypto.getRandomValues(new Uint8Array(12));
  const counter = new Uint8Array(16);
  counter.set(iv12, 0);
  const plainBuf = new TextEncoder().encode(plain);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter, length: 64 }, cryptoKey, plainBuf));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv12, 0);
  out.set(ct, 12);
  return 'ENC:' + uint8ToBase64(out);
}

export async function decryptString(maybeEnc: string, keyBase64: string): Promise<string> {
  if (!maybeEnc) return '';
  if (!maybeEnc.startsWith('ENC:')) return maybeEnc;
  if (!keyBase64) throw new Error('missing key');
  const data = base64ToUint8(maybeEnc.slice(4));
  if (data.length < 13) throw new Error('invalid payload');
  const iv12 = data.subarray(0, 12);
  const ct = data.subarray(12);
  const counter = new Uint8Array(16);
  counter.set(iv12, 0);
  const keyBytes = base64ToUint8(keyBase64);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-CTR', false, ['decrypt']);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-CTR', counter, length: 64 }, cryptoKey, ct);
  return new TextDecoder().decode(plainBuf);
}

export async function encryptKeyWithPublicKey(symKeyBase64: string, clientPubSpkiPem: string): Promise<string> {
  if (!symKeyBase64) throw new Error('missing symmetric key');
  if (!clientPubSpkiPem) throw new Error('missing public key');
  const spki = pemToArrayBuffer(clientPubSpkiPem);
  const pub = await crypto.subtle.importKey('spki', spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const keyBytes = base64ToUint8(symKeyBase64);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, keyBytes));
  return uint8ToBase64(ct);
}

function uint8ToBase64(u8: Uint8Array): string {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    const part = u8.subarray(i, i + chunk);
    s += String.fromCharCode.apply(null, Array.from(part));
  }
  return btoa(s);
}

function base64ToUint8(b64: string): Uint8Array {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  // strip header/footer and newlines
  const lines = pem.trim().split(/\r?\n/);
  // remove header/footer lines
  const filtered = lines.filter(l => !l.includes('-----BEGIN') && !l.includes('-----END'));
  const b64 = filtered.join('');
  return base64ToUint8(b64).buffer as ArrayBuffer;
}
