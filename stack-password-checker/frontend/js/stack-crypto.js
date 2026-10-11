/* StackCrypto — password-based AES-256-GCM encryption for text and files (Web Crypto API).
 *
 *  Key derivation : PBKDF2-HMAC-SHA-256, 600,000 iterations (default), fresh random 16-byte salt per encryption
 *  Cipher         : AES-256-GCM, fresh random 12-byte (96-bit) IV per encryption, 128-bit tag
 *  Authenticated  : the ciphertext AND the header (version, algorithms, iterations, salt) via GCM "additional data";
 *                   for files the original name/type/size are encrypted inside the authenticated plaintext.
 *  Nothing is stored or transmitted; no key is hard-coded; secrets are never logged.
 *
 * Text format  : Base64( JSON {v, alg, kdf, iter, salt, iv, ct} )
 * File format  : "STACKFE1" | uint32 headerLength | header JSON | AES-GCM( uint32 metaLength | meta JSON | file bytes )
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.StackCrypto = api;
})(typeof self !== 'undefined' ? self : globalThis, function (root) {
  'use strict';

  const VERSION = 1;
  const ALG = 'AES-256-GCM', KDF = 'PBKDF2-SHA256';
  const ITER_DEFAULT = 600000, ITER_MIN = 100000, ITER_MAX = 2000000;
  const SALT_LEN = 16, IV_LEN = 12, TAG_LEN = 16;
  const MIN_PASSWORD = 8;
  const MAX_TEXT_CIPHERTEXT = 8 * 1024 * 1024;       // bytes of ciphertext accepted when decrypting text
  const MAX_ENVELOPE_CHARS = 12 * 1024 * 1024;       // Base64 characters accepted when decrypting text
  const FILE_MAGIC = [0x53, 0x54, 0x41, 0x43, 0x4b, 0x46, 0x45, 0x31];   // "STACKFE1"
  const MAX_HEADER = 1024, MAX_META = 4096;

  class StackCryptoError extends Error {
    constructor(code, message) { super(message); this.name = 'StackCryptoError'; this.code = code; }
  }
  const fail = (code, msg) => { throw new StackCryptoError(code, msg); };
  const AUTH_MSG = 'Could not decrypt. The password is wrong, or the encrypted data was changed or damaged.';

  const subtle = () => {
    const s = root.crypto && root.crypto.subtle;
    if (!s) fail('NO_CRYPTO', 'Encryption needs the Web Crypto API. Open this page over HTTPS or on localhost, in an up-to-date browser.');
    return s;
  };
  const rand = n => root.crypto.getRandomValues(new Uint8Array(n));
  const utf8 = s => new TextEncoder().encode(s);

  /* ---------- Base64 (strict) ---------- */
  function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function b64ToBytes(str) {
    if (typeof str !== 'string' || str.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(str)) fail('BAD_FORMAT', 'This does not look like data produced by this tool.');
    const bin = atob(str), out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* ---------- key derivation ---------- */
  async function deriveKey(password, salt, iterations) {
    const s = subtle();
    // NFKC so the same typed password works however the keyboard/OS composes accented characters
    const base = await s.importKey('raw', utf8(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
    return s.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  function checkPasswordForEncrypt(password) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD) fail('BAD_INPUT', `Use an encryption password of at least ${MIN_PASSWORD} characters.`);
  }
  function checkPasswordForDecrypt(password) {
    if (typeof password !== 'string' || password.length === 0) fail('BAD_INPUT', 'Enter the encryption password.');
  }
  function iterationsOrDefault(opt) {
    const it = opt && opt.iterations !== undefined ? opt.iterations : ITER_DEFAULT;
    if (!Number.isInteger(it) || it < ITER_MIN || it > ITER_MAX) fail('BAD_INPUT', 'Unsupported iteration count.');
    return it;
  }
  const textAad = (iter, saltB64) => utf8(`STACK|${VERSION}|${ALG}|${KDF}|${iter}|${saltB64}`);

  /* ---------- text ---------- */
  async function encryptText(plaintext, password, options) {
    if (typeof plaintext !== 'string') fail('BAD_INPUT', 'Nothing to encrypt.');
    checkPasswordForEncrypt(password);
    const iter = iterationsOrDefault(options);
    const salt = rand(SALT_LEN), iv = rand(IV_LEN), saltB64 = bytesToB64(salt);
    const key = await deriveKey(password, salt, iter);
    const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: textAad(iter, saltB64), tagLength: TAG_LEN * 8 }, key, utf8(plaintext)));
    const env = { v: VERSION, alg: ALG, kdf: KDF, iter, salt: saltB64, iv: bytesToB64(iv), ct: bytesToB64(ct) };
    return bytesToB64(utf8(JSON.stringify(env)));
  }

  /** Validate an encrypted-text string and return its parts. Throws StackCryptoError; never runs the KDF. */
  function parseTextEnvelope(text) {
    if (typeof text !== 'string') fail('BAD_FORMAT', 'Paste the encrypted text first.');
    const clean = text.replace(/\s+/g, '');
    if (!clean) fail('BAD_FORMAT', 'Paste the encrypted text first.');
    if (clean.length > MAX_ENVELOPE_CHARS) fail('TOO_LARGE', 'This encrypted text is too large for this tool.');
    const jsonBytes = b64ToBytes(clean);
    let env;
    try { env = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(jsonBytes)); }
    catch (e) { fail('BAD_FORMAT', 'This does not look like data produced by this tool.'); }
    const keys = ['v', 'alg', 'kdf', 'iter', 'salt', 'iv', 'ct'];
    if (!env || typeof env !== 'object' || Array.isArray(env) || Object.keys(env).length !== keys.length || !keys.every(k => k in env)) fail('BAD_FORMAT', 'This does not look like data produced by this tool.');
    if (env.v !== VERSION || env.alg !== ALG || env.kdf !== KDF) fail('UNSUPPORTED', 'This encrypted text uses a version or algorithm this tool does not support.');
    if (!Number.isInteger(env.iter) || env.iter < ITER_MIN || env.iter > ITER_MAX) fail('UNSUPPORTED', 'This encrypted text uses an unsupported iteration count.');
    if (typeof env.salt !== 'string' || typeof env.iv !== 'string' || typeof env.ct !== 'string') fail('BAD_FORMAT', 'This does not look like data produced by this tool.');
    const salt = b64ToBytes(env.salt), iv = b64ToBytes(env.iv), ct = b64ToBytes(env.ct);
    if (salt.length !== SALT_LEN || iv.length !== IV_LEN || ct.length < TAG_LEN) fail('BAD_FORMAT', 'This encrypted text is incomplete or damaged.');
    if (ct.length > MAX_TEXT_CIPHERTEXT) fail('TOO_LARGE', 'This encrypted text is too large for this tool.');
    return { iter: env.iter, salt, saltB64: env.salt, iv, ct };
  }

  async function decryptText(envelopeText, password) {
    const e = parseTextEnvelope(envelopeText);
    checkPasswordForDecrypt(password);
    const key = await deriveKey(password, e.salt, e.iter);
    let plain;
    try { plain = await subtle().decrypt({ name: 'AES-GCM', iv: e.iv, additionalData: textAad(e.iter, e.saltB64), tagLength: TAG_LEN * 8 }, key, e.ct); }
    catch (err) { fail('AUTH_FAILED', AUTH_MSG); }
    try { return new TextDecoder('utf-8', { fatal: true }).decode(plain); }
    catch (err) { fail('AUTH_FAILED', AUTH_MSG); }
  }

  /* ---------- files ---------- */
  const u32 = n => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const readU32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

  /** data: Uint8Array of the original file bytes; meta: { name, type, lastModified }. Returns a Blob. */
  async function encryptFile(data, meta, password, options) {
    if (!(data instanceof Uint8Array)) fail('BAD_INPUT', 'No file data.');
    checkPasswordForEncrypt(password);
    const iter = iterationsOrDefault(options);
    const m = {
      name: String((meta && meta.name) || 'file').slice(0, 255),
      type: String((meta && meta.type) || '').slice(0, 255),
      size: data.length,
      lastModified: Number.isFinite(meta && meta.lastModified) ? meta.lastModified : 0
    };
    const metaBytes = utf8(JSON.stringify(m));
    if (metaBytes.length > MAX_META) fail('BAD_INPUT', 'The file name is too long.');
    const salt = rand(SALT_LEN), iv = rand(IV_LEN);
    const header = utf8(JSON.stringify({ v: VERSION, alg: ALG, kdf: KDF, iter, salt: bytesToB64(salt), iv: bytesToB64(iv) }));
    const prefix = new Uint8Array(8 + 4 + header.length);
    prefix.set(FILE_MAGIC, 0); prefix.set(u32(header.length), 8); prefix.set(header, 12);
    const plain = new Uint8Array(4 + metaBytes.length + data.length);
    plain.set(u32(metaBytes.length), 0); plain.set(metaBytes, 4); plain.set(data, 4 + metaBytes.length);
    const key = await deriveKey(password, salt, iter);
    const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: prefix, tagLength: TAG_LEN * 8 }, key, plain));
    plain.fill(0);
    return new Blob([prefix, ct], { type: 'application/octet-stream' });
  }

  function parseFileHeader(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12 + 2 + TAG_LEN + 4) fail('BAD_FORMAT', 'This is not an encrypted file made by this tool.');
    if (!FILE_MAGIC.every((v, i) => bytes[i] === v)) fail('BAD_FORMAT', 'This is not an encrypted file made by this tool.');
    const hlen = readU32(bytes, 8);
    if (hlen < 2 || hlen > MAX_HEADER || 12 + hlen + TAG_LEN + 4 > bytes.length) fail('BAD_FORMAT', 'This encrypted file is incomplete or damaged.');
    let h;
    try { h = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(12, 12 + hlen))); }
    catch (e) { fail('BAD_FORMAT', 'This encrypted file is incomplete or damaged.'); }
    const keys = ['v', 'alg', 'kdf', 'iter', 'salt', 'iv'];
    if (!h || typeof h !== 'object' || Array.isArray(h) || Object.keys(h).length !== keys.length || !keys.every(k => k in h)) fail('BAD_FORMAT', 'This encrypted file is incomplete or damaged.');
    if (h.v !== VERSION || h.alg !== ALG || h.kdf !== KDF) fail('UNSUPPORTED', 'This file uses a version or algorithm this tool does not support.');
    if (!Number.isInteger(h.iter) || h.iter < ITER_MIN || h.iter > ITER_MAX) fail('UNSUPPORTED', 'This file uses an unsupported iteration count.');
    if (typeof h.salt !== 'string' || typeof h.iv !== 'string') fail('BAD_FORMAT', 'This encrypted file is incomplete or damaged.');
    const salt = b64ToBytes(h.salt), iv = b64ToBytes(h.iv);
    if (salt.length !== SALT_LEN || iv.length !== IV_LEN) fail('BAD_FORMAT', 'This encrypted file is incomplete or damaged.');
    return { iter: h.iter, salt, iv, aad: bytes.subarray(0, 12 + hlen), ct: bytes.subarray(12 + hlen) };
  }

  /** Returns { name, type, size, lastModified, data: Uint8Array }. */
  async function decryptFile(bytes, password) {
    const p = parseFileHeader(bytes);
    checkPasswordForDecrypt(password);
    const key = await deriveKey(password, p.salt, p.iter);
    let plain;
    try { plain = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: p.iv, additionalData: p.aad, tagLength: TAG_LEN * 8 }, key, p.ct)); }
    catch (e) { fail('AUTH_FAILED', AUTH_MSG); }
    if (plain.length < 4) fail('AUTH_FAILED', AUTH_MSG);
    const mlen = readU32(plain, 0);
    if (mlen < 2 || mlen > MAX_META || 4 + mlen > plain.length) fail('AUTH_FAILED', AUTH_MSG);
    let m;
    try { m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain.subarray(4, 4 + mlen))); }
    catch (e) { fail('AUTH_FAILED', AUTH_MSG); }
    const data = plain.subarray(4 + mlen);
    if (!m || typeof m.name !== 'string' || typeof m.type !== 'string' || m.size !== data.length) fail('AUTH_FAILED', AUTH_MSG);
    return { name: m.name, type: m.type, size: data.length, lastModified: Number.isFinite(m.lastModified) ? m.lastModified : 0, data };
  }

  return { VERSION, ALG, KDF, ITER_DEFAULT, ITER_MIN, ITER_MAX, MIN_PASSWORD, StackCryptoError,
    encryptText, decryptText, parseTextEnvelope, encryptFile, decryptFile, parseFileHeader, bytesToB64, b64ToBytes };
});
