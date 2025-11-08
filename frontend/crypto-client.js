// Client-side crypto helpers for anonymous chat
// - Generates an RSA-OAEP key pair and stores PEMs in localStorage for session persistence
// - Exposes functions to get the public SPKI PEM and to decrypt server-wrapped messages
(function(){
  const PUB_KEY_STORAGE = 'anon_rsa_pub_pem_v1';
  const PRIV_KEY_STORAGE = 'anon_rsa_priv_pkcs8_pem_v1';

  function uint8ToBase64(u8) {
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) {
      const part = u8.subarray(i, i + chunk);
      s += String.fromCharCode.apply(null, Array.from(part));
    }
    return btoa(s);
  }
  function base64ToUint8(b64) {
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }

  function arrayBufferToBase64(buf) {
    return uint8ToBase64(new Uint8Array(buf));
  }
  function base64ToArrayBuffer(b64) {
    return base64ToUint8(b64).buffer;
  }

  function wrapPem(b64, label) {
    const chunkSize = 64;
    const lines = [];
    for (let i = 0; i < b64.length; i += chunkSize) lines.push(b64.slice(i, i + chunkSize));
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
  }

  async function exportPublicKeyToSpkiPem(key) {
    const spki = await crypto.subtle.exportKey('spki', key);
    const b64 = arrayBufferToBase64(spki);
    return wrapPem(b64, 'PUBLIC KEY');
  }

  async function exportPrivateKeyToPkcs8Pem(key) {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
    const b64 = arrayBufferToBase64(pkcs8);
    return wrapPem(b64, 'PRIVATE KEY');
  }

  async function importPrivateKeyFromPkcs8Pem(pem) {
    const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\s+/g, '');
    const ab = base64ToArrayBuffer(b64);
    return crypto.subtle.importKey('pkcs8', ab, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
  }

  async function ensureKeyPair() {
    try {
      const pub = localStorage.getItem(PUB_KEY_STORAGE);
      const priv = localStorage.getItem(PRIV_KEY_STORAGE);
      if (pub && priv) {
        // attempt to import private key to verify it works
        try {
          await importPrivateKeyFromPkcs8Pem(priv);
          return { pubPem: pub, privPem: priv };
        } catch (e) {
          // fall through to regenerate
        }
      }
    } catch (e) { /* localStorage may throw in some contexts */ }

    // generate a new RSA-OAEP key pair (2048-bit, SHA-256)
    const kp = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['encrypt','decrypt']);
    const pubPem = await exportPublicKeyToSpkiPem(kp.publicKey);
    const privPem = await exportPrivateKeyToPkcs8Pem(kp.privateKey);
    try {
      localStorage.setItem(PUB_KEY_STORAGE, pubPem);
      localStorage.setItem(PRIV_KEY_STORAGE, privPem);
    } catch (e) {}
    return { pubPem, privPem };
  }

  function getStoredPublicPem() {
    try { return localStorage.getItem(PUB_KEY_STORAGE) || null; } catch (e) { return null; }
  }

  async function getPrivateKeyCryptoKey() {
    const privPem = (() => { try { return localStorage.getItem(PRIV_KEY_STORAGE); } catch (e) { return null; } })();
    if (!privPem) return null;
    try { return await importPrivateKeyFromPkcs8Pem(privPem); } catch (e) { return null; }
  }

  async function decryptWrappedKeyToBase64(wrappedB64) {
    // wrappedB64 is base64 of RSA-OAEP ciphertext that decrypts to raw symmetric key bytes
    const priv = await getPrivateKeyCryptoKey();
    if (!priv) throw new Error('private key not available');
    const ct = base64ToArrayBuffer(wrappedB64);
    const symBuf = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, ct);
    // return symmetric key as base64
    return arrayBufferToBase64(symBuf);
  }

  async function aesDecryptString(maybeEnc, keyBase64) {
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

  async function decryptMessagePayload(payload) {
    // payload can be string or { cipher, wrapped_key }
    try {
      if (!payload) return '';
      if (typeof payload === 'string') return payload;
      const cipher = payload.cipher || payload.cipher_text || payload.ciphertext || payload.cipherText;
      const wrapped = payload.wrapped_key || payload.wrappedKey || payload.wrapped || payload.wrappedKeyB64;
      if (!cipher) return '';
      if (!wrapped) {
        // no wrapped key: assume cipher contains plaintext form
        return cipher;
      }
      const symB64 = await decryptWrappedKeyToBase64(wrapped);
      const plain = await aesDecryptString(cipher, symB64);
      return plain;
    } catch (e) {
      console.warn('decryptMessagePayload error', e);
      return '';
    }
  }

  // Expose a simple API on window
  window.cryptoClient = {
    ensureKeyPair,
    getPublicPem: function() { return getStoredPublicPem(); },
    decryptMessagePayload,
  };

})();
