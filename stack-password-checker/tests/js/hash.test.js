const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const H = require('../../frontend/js/stack-hash.js');

const nodeName = a => a.replace('-', '').toLowerCase();

test('known vectors', async () => {
  assert.equal(await H.digestText('SHA-256', 'hello'), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  assert.equal(await H.digestText('SHA-256', ''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(await H.digestText('SHA-512', 'abc'),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
});

test('incremental SHA-2 matches Node crypto across block boundaries and random chunking', () => {
  const lens = [0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129, 255, 256, 1000, 70000];
  for (const algo of Object.keys(H.ALGOS)) for (const L of lens) {
    const data = nodeCrypto.randomBytes(L);
    const expected = nodeCrypto.createHash(nodeName(algo)).update(data).digest('hex');
    const h = H.createHasher(algo);
    for (let i = 0; i < L;) { const k = 1 + Math.floor(Math.random() * 200); h.update(data.subarray(i, i + k)); i += k; }
    assert.equal(h.hex(), expected, `${algo} length ${L}`);
  }
});

test('hashBlob: Web Crypto path and streaming path agree with Node and each other', async () => {
  const data = nodeCrypto.randomBytes(1_300_000);
  const blob = new Blob([data]);
  for (const algo of Object.keys(H.ALGOS)) {
    const expected = nodeCrypto.createHash(nodeName(algo)).update(data).digest('hex');
    const seen = [];
    const a = await H.hashBlob(blob, algo, { onProgress: v => seen.push(v), chunkSize: 200_000 });
    const b = await H.hashBlob(blob, algo, { thresholdBytes: 0, chunkSize: 200_000, useWorker: false });
    assert.equal(a.method, 'webcrypto'); assert.equal(b.method, 'stream');
    assert.equal(a.hex, expected); assert.equal(b.hex, expected);
    assert.equal(seen[seen.length - 1], 1);
  }
});

test('hashBlob: empty file and cancellation', async () => {
  const empty = await H.hashBlob(new Blob([]), 'SHA-256');
  assert.equal(empty.hex, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  const ctl = new AbortController(); ctl.abort();
  await assert.rejects(() => H.hashBlob(new Blob(['x']), 'SHA-256', { signal: ctl.signal }), { name: 'AbortError' });
  await assert.rejects(() => H.hashBlob(new Blob(['x']), 'MD5'), /Unsupported/);
});

test('same bytes, same hash; one changed bit, different hash', async () => {
  const a = nodeCrypto.randomBytes(5000), b = Buffer.from(a); b[100] ^= 1;
  const [h1, h2, h3] = await Promise.all([a, a, b].map(d => H.hashBlob(new Blob([d]), 'SHA-256')));
  assert.equal(h1.hex, h2.hex); assert.notEqual(h1.hex, h3.hex);
});

test('normalizeReference', () => {
  const h = '2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824';
  let r = H.normalizeReference('  ' + h + '\n');
  assert.ok(r.ok); assert.equal(r.hex, h.toLowerCase()); assert.equal(r.algo, 'SHA-256');
  r = H.normalizeReference(h.toLowerCase() + '  hello.txt');
  assert.ok(r.ok); assert.equal(r.hex.length, 64); assert.ok(r.note);
  assert.equal(H.normalizeReference('').error, 'empty');
  assert.equal(H.normalizeReference('zz'.repeat(32)).error, 'not-hex');
  assert.equal(H.normalizeReference('abc').algo, null);
  assert.equal(H.normalizeReference('a'.repeat(128)).algo, 'SHA-512');
});
