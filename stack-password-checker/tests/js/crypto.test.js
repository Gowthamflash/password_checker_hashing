const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../../frontend/js/stack-crypto.js');

const FAST = { iterations: 100000 };      // the app default is 600,000; tests use the minimum to stay quick
const PW = 'correct horse battery';
const flipB64 = (b64, idx) => { const b = C.b64ToBytes(b64); b[idx] ^= 1; return C.bytesToB64(b); };
const editEnv = (env, fn) => { const o = JSON.parse(Buffer.from(env, 'base64').toString('utf8')); fn(o); return Buffer.from(JSON.stringify(o)).toString('base64'); };
const code = async p => { try { await p; return 'no error'; } catch (e) { return e.code || e.name; } };

test('defaults are strong', () => {
  assert.equal(C.ITER_DEFAULT, 600000); assert.equal(C.ALG, 'AES-256-GCM'); assert.equal(C.KDF, 'PBKDF2-SHA256');
});

test('text round trip: ASCII, unicode, emoji, multiline', async () => {
  for (const msg of ['hello', 'Zażółć gęślą jaźń — ünïcödé 日本語', '👩‍💻🔐', 'line1\nline2\r\n\ttabbed', 'x'.repeat(100000)]) {
    const env = await C.encryptText(msg, PW, FAST);
    assert.equal(await C.decryptText(env, PW), msg);
  }
});

test('envelope structure and fresh salt/IV every time; plaintext not visible', async () => {
  const a = await C.encryptText('hello', PW, FAST), b = await C.encryptText('hello', PW, FAST);
  assert.notEqual(a, b);
  const ea = JSON.parse(Buffer.from(a, 'base64').toString()), eb = JSON.parse(Buffer.from(b, 'base64').toString());
  assert.deepEqual(Object.keys(ea).sort(), ['alg', 'ct', 'iter', 'iv', 'kdf', 'salt', 'v']);
  assert.equal(ea.v, 1); assert.equal(ea.alg, 'AES-256-GCM'); assert.equal(ea.kdf, 'PBKDF2-SHA256'); assert.equal(ea.iter, 100000);
  assert.equal(C.b64ToBytes(ea.salt).length, 16); assert.equal(C.b64ToBytes(ea.iv).length, 12);
  assert.notEqual(ea.salt, eb.salt); assert.notEqual(ea.iv, eb.iv);
  assert.ok(!a.includes('hello') && !Buffer.from(a, 'base64').toString().includes('hello'));
  assert.equal(C.b64ToBytes(ea.ct).length, 5 + 16);       // plaintext + GCM tag
});

test('wrong password and tampering are rejected with the same safe error', async () => {
  const env = await C.encryptText('secret message', PW, FAST);
  assert.equal(await code(C.decryptText(env, 'wrong password')), 'AUTH_FAILED');
  const o = JSON.parse(Buffer.from(env, 'base64').toString());
  for (const [name, mut] of [
    ['ciphertext bit', e => { e.ct = flipB64(e.ct, 0); }],
    ['tag bit', e => { e.ct = flipB64(e.ct, C.b64ToBytes(e.ct).length - 1); }],
    ['iv bit', e => { e.iv = flipB64(e.iv, 0); }],
    ['salt bit', e => { e.salt = flipB64(e.salt, 3); }],
    ['iteration count', e => { e.iter += 1; }]
  ]) assert.equal(await code(C.decryptText(editEnv(env, mut), PW)), 'AUTH_FAILED', name);
  assert.equal(o.iter, 100000);
});

test('malformed or hostile envelopes are rejected before any key derivation', async () => {
  const env = await C.encryptText('x', PW, FAST);
  const bad = [
    ['', 'BAD_FORMAT'], ['not base64!!', 'BAD_FORMAT'], [Buffer.from('plain text').toString('base64'), 'BAD_FORMAT'],
    [Buffer.from('[1,2,3]').toString('base64'), 'BAD_FORMAT'],
    [editEnv(env, e => { e.v = 2; }), 'UNSUPPORTED'], [editEnv(env, e => { e.alg = 'AES-128-CBC'; }), 'UNSUPPORTED'],
    [editEnv(env, e => { e.kdf = 'MD5'; }), 'UNSUPPORTED'],
    [editEnv(env, e => { e.iter = 900000000; }), 'UNSUPPORTED'], [editEnv(env, e => { e.iter = 10; }), 'UNSUPPORTED'],
    [editEnv(env, e => { e.iter = '600000'; }), 'UNSUPPORTED'],
    [editEnv(env, e => { e.salt = Buffer.from('short').toString('base64'); }), 'BAD_FORMAT'],
    [editEnv(env, e => { e.iv = Buffer.alloc(16).toString('base64'); }), 'BAD_FORMAT'],
    [editEnv(env, e => { e.ct = Buffer.alloc(8).toString('base64'); }), 'BAD_FORMAT'],
    [editEnv(env, e => { e.extra = 1; }), 'BAD_FORMAT'], [editEnv(env, e => { delete e.iv; }), 'BAD_FORMAT']
  ];
  const t0 = Date.now();
  for (const [input, want] of bad) assert.equal(await code(C.decryptText(input, PW)), want, input.slice(0, 30));
  assert.ok(Date.now() - t0 < 1500, 'validation must not run PBKDF2');
});

test('whitespace/line wrapping in pasted ciphertext is tolerated', async () => {
  const env = await C.encryptText('wrapped', PW, FAST);
  const wrapped = env.replace(/(.{40})/g, '$1\n  ');
  assert.equal(await C.decryptText(wrapped, PW), 'wrapped');
});

test('password rules', async () => {
  assert.equal(await code(C.encryptText('x', 'short', FAST)), 'BAD_INPUT');
  assert.equal(await code(C.encryptText('x', PW, { iterations: 5 })), 'BAD_INPUT');
  const env = await C.encryptText('x', PW, FAST);
  assert.equal(await code(C.decryptText(env, '')), 'BAD_INPUT');
  // composed vs decomposed accents are the same password (NFKC)
  const e2 = await C.encryptText('ok', 'caf\u00e9-pass-1', FAST);
  assert.equal(await C.decryptText(e2, 'cafe\u0301-pass-1'), 'ok');
});

const bytesOf = async blob => new Uint8Array(await blob.arrayBuffer());

test('file round trip keeps bytes and metadata; name is not visible in the output', async () => {
  const data = new Uint8Array(200000).map((_, i) => (i * 31 + 7) & 255);
  const blob = await C.encryptFile(data, { name: 'holiday photo (1).png', type: 'image/png', lastModified: 1700000000000 }, PW, FAST);
  const enc = await bytesOf(blob);
  assert.equal(Buffer.from(enc.subarray(0, 8)).toString(), 'STACKFE1');
  assert.ok(!Buffer.from(enc).includes('holiday'));
  assert.ok(enc.length >= data.length + 16);
  const out = await C.decryptFile(enc, PW);
  assert.equal(out.name, 'holiday photo (1).png'); assert.equal(out.type, 'image/png'); assert.equal(out.size, data.length);
  assert.equal(out.lastModified, 1700000000000); assert.deepEqual(Buffer.from(out.data), Buffer.from(data));
});

test('empty file round trip', async () => {
  const enc = await bytesOf(await C.encryptFile(new Uint8Array(0), { name: 'empty.txt', type: 'text/plain' }, PW, FAST));
  const out = await C.decryptFile(enc, PW);
  assert.equal(out.size, 0); assert.equal(out.name, 'empty.txt');
});

test('file: wrong password, tampering, truncation, wrong magic', async () => {
  const enc = await bytesOf(await C.encryptFile(new TextEncoder().encode('important'), { name: 'a.txt', type: 'text/plain' }, PW, FAST));
  assert.equal(await code(C.decryptFile(enc, 'nope nope nope')), 'AUTH_FAILED');
  const hlen = new DataView(enc.buffer, enc.byteOffset).getUint32(8);
  const flip = i => { const c = new Uint8Array(enc); c[i] ^= 1; return c; };
  assert.equal(await code(C.decryptFile(flip(enc.length - 1), PW)), 'AUTH_FAILED', 'tag');
  assert.equal(await code(C.decryptFile(flip(12 + hlen + 2), PW)), 'AUTH_FAILED', 'ciphertext');
  assert.notEqual(await code(C.decryptFile(flip(12 + 20), PW)), 'no error', 'header');
  assert.equal(await code(C.decryptFile(enc.subarray(0, enc.length - 5), PW)), 'AUTH_FAILED', 'truncated');
  assert.equal(await code(C.decryptFile(enc.subarray(0, 20), PW)), 'BAD_FORMAT', 'too short');
  assert.equal(await code(C.decryptFile(flip(0), PW)), 'BAD_FORMAT', 'magic');
  assert.equal(await code(C.decryptFile(new Uint8Array(100), PW)), 'BAD_FORMAT', 'zeros');
  const huge = new Uint8Array(enc); new DataView(huge.buffer).setUint32(8, 0x7fffffff);
  assert.equal(await code(C.decryptFile(huge, PW)), 'BAD_FORMAT', 'absurd header length');
});

test('file: same file encrypted twice gives different output', async () => {
  const d = new TextEncoder().encode('same');
  const a = await bytesOf(await C.encryptFile(d, { name: 'a' }, PW, FAST)), b = await bytesOf(await C.encryptFile(d, { name: 'a' }, PW, FAST));
  assert.notDeepEqual(Buffer.from(a), Buffer.from(b));
});
