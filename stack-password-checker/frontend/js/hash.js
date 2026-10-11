/* Hash Generator page: SHA-256 / SHA-384 / SHA-512 of text, computed locally.
 * The entered text is never sent, stored, logged or included in the downloaded file. */
(() => {
  'use strict';
  const S = window.Stack, H = window.StackHash;
  const $ = s => document.querySelector(s);
  const el = { inp: $('#hIn'), algo: $('#hAlgo'), go: $('#hGo'), ex: $('#hEx'), clear: $('#hClear'), msg: $('#hMsg'),
    result: $('#hResult'), out: $('#hOut'), algoOut: $('#hAlgoOut'), lenOut: $('#hLenOut'), copy: $('#hCopy'), down: $('#hDown') };
  let last = null;                                   // { algo, hex, bytes } of the displayed result

  function hideResult() { el.result.hidden = true; last = null; el.out.textContent = ''; }
  async function generate() {
    const text = el.inp.value;
    if (!text) { hideResult(); S.status(el.msg, 'bad', 'Enter some text to hash.'); el.inp.focus(); return; }
    const algo = el.algo.value;
    try {
      const hex = await H.digestText(algo, text);
      const info = H.ALGOS[algo];
      last = { algo, hex, bytes: new TextEncoder().encode(text).length };
      el.out.textContent = hex;
      el.algoOut.textContent = algo;
      el.lenOut.textContent = `${info.bits} bits (${info.hexLen} hexadecimal characters)`;
      el.result.hidden = false;
      S.status(el.msg, 'ok', `${algo} hash generated.`);
    } catch (e) {
      hideResult(); S.status(el.msg, 'bad', 'Could not create the hash in this browser.');
    }
  }
  el.go.addEventListener('click', generate);
  el.algo.addEventListener('change', () => { if (last) generate(); });
  el.inp.addEventListener('input', () => { if (last) { hideResult(); S.status(el.msg, '', ''); } });   // never show a hash for stale text
  el.ex.addEventListener('click', () => { el.inp.value = 'hello'; generate(); });
  el.clear.addEventListener('click', () => { el.inp.value = ''; hideResult(); S.status(el.msg, '', ''); el.inp.focus(); });
  el.copy.addEventListener('click', async () => { if (last) S.toast((await S.copyText(last.hex)) ? 'Hash copied.' : 'Could not copy. Select the hash and copy it manually.'); });
  el.down.addEventListener('click', () => {
    if (!last) return;
    const name = last.algo.toLowerCase().replace('-', '');
    S.downloadText(['Stack Password Checking and Hashing', `Algorithm: ${last.algo}`, `Input: text, ${last.bytes} bytes (UTF-8)`,
      `Hash: ${last.hex}`, `Generated: ${S.stamp()}`, ''].join('\n'), `${name}-hash.txt`);
    S.toast('Download started.');
  });
  addEventListener('pageshow', e => { if (e.persisted) { el.inp.value = ''; hideResult(); } });
})();
