/* Web Worker: streaming file hash. Reads the file in chunks so memory use stays small.
 * Receives { type: 'hash', file, algo, chunkSize }; replies with progress / done / error messages.
 * It never touches the network. */
'use strict';
importScripts('stack-hash.js');

self.onmessage = async ev => {
  const m = ev.data || {};
  if (m.type !== 'hash') return;
  try {
    const h = self.StackHash.createHasher(m.algo);
    const file = m.file, size = file.size, chunk = Math.max(64 * 1024, m.chunkSize | 0 || 4 * 1024 * 1024);
    let off = 0, last = 0;
    while (off < size) {
      const end = Math.min(size, off + chunk);
      h.update(new Uint8Array(await file.slice(off, end).arrayBuffer()));
      off = end;
      const now = Date.now();
      if (now - last > 80) { last = now; self.postMessage({ type: 'progress', value: off / size }); }
    }
    self.postMessage({ type: 'done', hex: h.hex() });
  } catch (err) {
    self.postMessage({ type: 'error', message: 'This file could not be read. It may be a folder, or access may have been denied.' });
  }
};
