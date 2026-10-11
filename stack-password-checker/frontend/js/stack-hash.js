/* StackHash — hashing helpers used by the Hash, File Hash and Verify tools.
 *
 *  - Text and small files are hashed with the browser's Web Crypto API (crypto.subtle.digest).
 *  - Large files are hashed in a streaming way (one chunk at a time, inside a Web Worker when possible)
 *    with the incremental SHA-2 implementation below, because Web Crypto cannot hash incrementally.
 *    Both paths hash the exact original bytes and give identical results (see tests/js/hash.test.js).
 *  - Nothing here touches the network, storage or the console.
 *
 * Works in the page, in a Web Worker (importScripts) and in Node.js (module.exports) for tests.
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.StackHash = api;
})(typeof self !== 'undefined' ? self : globalThis, function (root) {
  'use strict';

  const ALGOS = {
    'SHA-256': { bits: 256, hexLen: 64 },
    'SHA-384': { bits: 384, hexLen: 96 },
    'SHA-512': { bits: 512, hexLen: 128 }
  };
  const algoByHexLen = len => Object.keys(ALGOS).find(a => ALGOS[a].hexLen === len) || null;

  /* ---------- SHA-2 constants, derived from the first primes (avoids typo-prone tables) ---------- */
  function primes(n) {
    const out = [];
    for (let c = 2; out.length < n; c++) if (out.every(p => c % p)) out.push(c);
    return out;
  }
  function isqrt(n) {
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / 2));
    for (;;) { const y = (x + n / x) >> 1n; if (y >= x) return x; x = y; }
  }
  function icbrt(n) {
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3));
    for (;;) { const y = (2n * x + n / (x * x)) / 3n; if (y >= x) return x; x = y; }
  }
  const M32 = 0xffffffffn, M64 = (1n << 64n) - 1n;
  const P = primes(80);
  const K256 = Uint32Array.from(P.slice(0, 64), p => Number(icbrt(BigInt(p) << 96n) & M32));
  const H256 = Uint32Array.from(P.slice(0, 8), p => Number(isqrt(BigInt(p) << 64n) & M32));
  const K512 = new Uint32Array(160);               // [hi, lo] pairs
  P.forEach((p, i) => { const v = icbrt(BigInt(p) << 192n) & M64; K512[2 * i] = Number(v >> 32n); K512[2 * i + 1] = Number(v & M32); });
  function init512(slice) {
    const h = new Uint32Array(16);
    P.slice(slice, slice + 8).forEach((p, i) => { const v = isqrt(BigInt(p) << 128n) & M64; h[2 * i] = Number(v >> 32n); h[2 * i + 1] = Number(v & M32); });
    return h;
  }
  const H512 = init512(0), H384 = init512(8);
  const TWO32 = 4294967296;

  const hexWord = w => ('00000000' + (w >>> 0).toString(16)).slice(-8);

  /* ---------- shared buffering / padding ---------- */
  class Base {
    constructor(blockSize, lenOffset) {
      this.bs = blockSize; this.lo = lenOffset;
      this.buf = new Uint8Array(blockSize); this.n = 0; this.len = 0; this.done = false;
    }
    update(data) {
      if (this.done) throw new Error('Hasher already finished');
      const bs = this.bs, len = data.length;
      this.len += len;
      let i = 0;
      if (this.n) {
        const take = Math.min(bs - this.n, len);
        this.buf.set(data.subarray(0, take), this.n);
        this.n += take; i = take;
        if (this.n === bs) { this._block(this.buf, 0); this.n = 0; }
      }
      for (; i + bs <= len; i += bs) this._block(data, i);
      if (i < len) { this.buf.set(data.subarray(i), 0); this.n = len - i; }
      return this;
    }
    _finish() {
      if (this.done) throw new Error('Hasher already finished');
      this.done = true;
      const b = this.buf, bs = this.bs;
      b[this.n++] = 0x80;
      if (this.n > this.lo) { b.fill(0, this.n, bs); this._block(b, 0); this.n = 0; }
      b.fill(0, this.n, bs);
      const hi = Math.floor(this.len / 0x20000000), lo = ((this.len % 0x20000000) * 8) >>> 0;   // length in bits
      const o = bs - 8;
      b[o] = hi >>> 24; b[o + 1] = hi >>> 16; b[o + 2] = hi >>> 8; b[o + 3] = hi;
      b[o + 4] = lo >>> 24; b[o + 5] = lo >>> 16; b[o + 6] = lo >>> 8; b[o + 7] = lo;
      this._block(b, 0);
    }
  }

  class Sha256 extends Base {
    constructor() { super(64, 56); this.h = Uint32Array.from(H256); this.w = new Uint32Array(64); }
    _block(p, off) {
      const w = this.w, h = this.h;
      for (let t = 0; t < 16; t++) { const j = off + t * 4; w[t] = ((p[j] << 24) | (p[j + 1] << 16) | (p[j + 2] << 8) | p[j + 3]) >>> 0; }
      for (let t = 16; t < 64; t++) {
        const x = w[t - 15], y = w[t - 2];
        const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let t = 0; t < 64; t++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K256[t] + w[t]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    hex() { this._finish(); return Array.from(this.h, hexWord).join(''); }
  }

  class Sha512 extends Base {
    constructor(is384) { super(128, 112); this.h = Uint32Array.from(is384 ? H384 : H512); this.words = is384 ? 12 : 16; this.w = new Uint32Array(160); }
    _block(p, off) {
      const w = this.w, h = this.h;
      for (let t = 0; t < 32; t++) { const j = off + t * 4; w[t] = ((p[j] << 24) | (p[j + 1] << 16) | (p[j + 2] << 8) | p[j + 3]) >>> 0; }
      for (let t = 16; t < 80; t++) {
        const xh = w[2 * (t - 15)], xl = w[2 * (t - 15) + 1];
        const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
        const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
        const yh = w[2 * (t - 2)], yl = w[2 * (t - 2) + 1];
        const s1h = ((yh >>> 19) | (yl << 13)) ^ ((yl >>> 29) | (yh << 3)) ^ (yh >>> 6);
        const s1l = ((yl >>> 19) | (yh << 13)) ^ ((yh >>> 29) | (yl << 3)) ^ ((yl >>> 6) | (yh << 26));
        const lo = w[2 * (t - 16) + 1] + (s0l >>> 0) + w[2 * (t - 7) + 1] + (s1l >>> 0);
        const hi = w[2 * (t - 16)] + (s0h >>> 0) + w[2 * (t - 7)] + (s1h >>> 0) + Math.floor(lo / TWO32);
        w[2 * t] = hi; w[2 * t + 1] = lo;     // Uint32Array stores wrap modulo 2^32
      }
      let aH = h[0], aL = h[1], bH = h[2], bL = h[3], cH = h[4], cL = h[5], dH = h[6], dL = h[7];
      let eH = h[8], eL = h[9], fH = h[10], fL = h[11], gH = h[12], gL = h[13], hH = h[14], hL = h[15];
      for (let t = 0; t < 80; t++) {
        const S1h = ((eH >>> 14) | (eL << 18)) ^ ((eH >>> 18) | (eL << 14)) ^ ((eL >>> 9) | (eH << 23));
        const S1l = ((eL >>> 14) | (eH << 18)) ^ ((eL >>> 18) | (eH << 14)) ^ ((eH >>> 9) | (eL << 23));
        const chH = (eH & fH) ^ (~eH & gH), chL = (eL & fL) ^ (~eL & gL);
        const t1lo = (hL >>> 0) + (S1l >>> 0) + (chL >>> 0) + K512[2 * t + 1] + w[2 * t + 1];
        const t1h = ((hH >>> 0) + (S1h >>> 0) + (chH >>> 0) + K512[2 * t] + w[2 * t] + Math.floor(t1lo / TWO32)) >>> 0;
        const t1l = t1lo >>> 0;
        const S0h = ((aH >>> 28) | (aL << 4)) ^ ((aL >>> 2) | (aH << 30)) ^ ((aL >>> 7) | (aH << 25));
        const S0l = ((aL >>> 28) | (aH << 4)) ^ ((aH >>> 2) | (aL << 30)) ^ ((aH >>> 7) | (aL << 25));
        const mjH = (aH & bH) ^ (aH & cH) ^ (bH & cH), mjL = (aL & bL) ^ (aL & cL) ^ (bL & cL);
        const t2lo = (S0l >>> 0) + (mjL >>> 0);
        const t2h = ((S0h >>> 0) + (mjH >>> 0) + Math.floor(t2lo / TWO32)) >>> 0;
        const t2l = t2lo >>> 0;
        hH = gH; hL = gL; gH = fH; gL = fL; fH = eH; fL = eL;
        const elo = (dL >>> 0) + t1l;
        eH = ((dH >>> 0) + t1h + Math.floor(elo / TWO32)) >>> 0; eL = elo >>> 0;
        dH = cH; dL = cL; cH = bH; cL = bL; bH = aH; bL = aL;
        const alo = t1l + t2l;
        aH = (t1h + t2h + Math.floor(alo / TWO32)) >>> 0; aL = alo >>> 0;
      }
      const st = [aH, aL, bH, bL, cH, cL, dH, dL, eH, eL, fH, fL, gH, gL, hH, hL];
      for (let i = 0; i < 16; i += 2) {
        const lo = (h[i + 1] >>> 0) + (st[i + 1] >>> 0);
        h[i] = (h[i] >>> 0) + (st[i] >>> 0) + Math.floor(lo / TWO32);
        h[i + 1] = lo;
      }
    }
    hex() { this._finish(); return Array.from(this.h.subarray(0, this.words), hexWord).join(''); }
  }

  function createHasher(algo) {
    if (algo === 'SHA-256') return new Sha256();
    if (algo === 'SHA-384') return new Sha512(true);
    if (algo === 'SHA-512') return new Sha512(false);
    throw new Error('Unsupported algorithm');
  }

  /* ---------- Web Crypto helpers ---------- */
  const subtleOrNull = () => (root.crypto && root.crypto.subtle) || null;
  const toHex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  const utf8 = s => new TextEncoder().encode(s);

  async function digestBytes(algo, bytes) {
    if (!ALGOS[algo]) throw new Error('Unsupported algorithm');
    const s = subtleOrNull();
    if (s) return toHex(await s.digest(algo, bytes));
    return createHasher(algo).update(bytes).hex();          // e.g. plain-HTTP pages where Web Crypto is unavailable
  }
  const digestText = (algo, text) => digestBytes(algo, utf8(text));

  /* ---------- file hashing ---------- */
  const abortError = () => new DOMException('Hashing was cancelled.', 'AbortError');
  const throwIfAborted = sig => { if (sig && sig.aborted) throw abortError(); };

  async function viaWebCrypto(blob, algo, o) {
    const size = blob.size, buf = new Uint8Array(size);
    let off = 0;
    while (off < size) {
      throwIfAborted(o.signal);
      const end = Math.min(size, off + o.chunkSize);
      buf.set(new Uint8Array(await blob.slice(off, end).arrayBuffer()), off);
      off = end; o.onProgress(off / size * 0.95);
    }
    throwIfAborted(o.signal);
    const hex = toHex(await subtleOrNull().digest(algo, buf));
    o.onProgress(1);
    return hex;
  }
  async function viaMainThread(blob, algo, o) {
    const h = createHasher(algo), size = blob.size;
    let off = 0;
    while (off < size) {
      throwIfAborted(o.signal);
      const end = Math.min(size, off + o.chunkSize);
      h.update(new Uint8Array(await blob.slice(off, end).arrayBuffer()));
      off = end; o.onProgress(off / size);
      await new Promise(r => setTimeout(r, 0));             // let the page breathe between chunks
    }
    return h.hex();
  }
  function viaWorker(blob, algo, o) {
    return new Promise((resolve, reject) => {
      let worker;
      try { worker = new Worker(o.workerUrl); }
      catch (e) { const err = new Error('Worker unavailable'); err.workerUnavailable = true; return reject(err); }
      let started = false, settled = false;
      const finish = (fn, v) => { if (settled) return; settled = true; if (o.signal) o.signal.removeEventListener('abort', onAbort); worker.terminate(); fn(v); };
      const onAbort = () => finish(reject, abortError());
      if (o.signal) o.signal.addEventListener('abort', onAbort);
      worker.onmessage = ev => {
        const m = ev.data || {};
        started = true;
        if (m.type === 'progress') o.onProgress(m.value);
        else if (m.type === 'done') { o.onProgress(1); finish(resolve, m.hex); }
        else if (m.type === 'error') finish(reject, Object.assign(new Error(m.message || 'Could not read the file.'), { readError: true }));
      };
      worker.onerror = ev => {
        if (ev && ev.preventDefault) ev.preventDefault();
        const err = new Error('Worker failed'); err.workerUnavailable = !started; finish(reject, err);
      };
      worker.postMessage({ type: 'hash', file: blob, algo, chunkSize: o.chunkSize });
    });
  }

  /**
   * Hash a File/Blob. Returns { hex, method } where method is 'webcrypto', 'worker-stream' or 'stream'.
   * options: onProgress(0..1), signal (AbortSignal), thresholdBytes, chunkSize, workerUrl, useWorker
   */
  async function hashBlob(blob, algo, options) {
    if (!ALGOS[algo]) throw new Error('Unsupported algorithm');
    const o = Object.assign({ thresholdBytes: 64 * 1024 * 1024, chunkSize: 4 * 1024 * 1024, onProgress() {}, signal: null,
      workerUrl: 'js/hash-worker.js', useWorker: true }, options || {});
    throwIfAborted(o.signal);
    o.onProgress(0);
    if (subtleOrNull() && blob.size <= o.thresholdBytes) return { hex: await viaWebCrypto(blob, algo, o), method: 'webcrypto' };
    if (o.useWorker && typeof Worker !== 'undefined') {
      try { return { hex: await viaWorker(blob, algo, o), method: 'worker-stream' }; }
      catch (e) { if (!e.workerUnavailable) throw e; }
    }
    return { hex: await viaMainThread(blob, algo, o), method: 'stream' };
  }

  /* ---------- reference-hash parsing (Hash Verification) ---------- */
  function normalizeReference(input) {
    let s = String(input == null ? '' : input).trim();
    if (!s) return { ok: false, error: 'empty' };
    let note = '';
    // Accept the output of sha256sum / shasum:  "<hash>  filename"  or  "<hash> *filename"
    const m = s.match(/^([0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})\s+\*?\S[\s\S]*$/);
    if (m) { s = m[1]; note = 'Used the first value (the hash) and ignored the file name that followed it.'; }
    s = s.toLowerCase();
    if (!/^[0-9a-f]+$/.test(s)) return { ok: false, error: 'not-hex' };
    return { ok: true, hex: s, length: s.length, algo: algoByHexLen(s.length), note };
  }

  return { ALGOS, algoByHexLen, createHasher, digestBytes, digestText, hashBlob, normalizeReference, toHex };
});
