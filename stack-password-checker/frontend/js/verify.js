/* Hash Verification page: hash a file locally, then compare it with a pasted reference hash. */
(() => {
  'use strict';
  const S = window.Stack, H = window.StackHash, cfg = S.cfg();
  const $ = s => document.querySelector(s);
  const el = { drop: $('#drop'), browse: $('#browse'), input: $('#fileIn'), algo: $('#vAlgo'), cancel: $('#vCancel'), msg: $('#vMsg'),
    file: $('#vFile'), computed: $('#vComputed'), algoOut: $('#vAlgoOut'), hash: $('#vHash'), copy: $('#vCopy'),
    ref: $('#vRef'), refMsg: $('#vRefMsg'), verdict: $('#verdict'), vt: $('#vVerdict'), vd: $('#vVerdictText'), clear: $('#vClear') };
  let file = null, hex = '', hexAlgo = '', ctl = null, thumbUrl = null, runId = 0, lastKind = 'waiting';

  S.dropzone(el.drop, el.input, files => { if (files[0]) setFile(files[0]); });

  function showFile() {
    el.file.textContent = '';
    if (!file) { el.file.hidden = true; return; }
    el.file.hidden = false; el.file.style.gridTemplateColumns = '60px 1fr auto';
    const th = document.createElement('div'); th.className = 'th';
    if (thumbUrl) { const img = document.createElement('img'); img.src = thumbUrl; img.alt = 'Preview of ' + file.name; img.addEventListener('error', () => { img.remove(); th.innerHTML = S.icon('image', 24); }); th.appendChild(img); }
    else th.innerHTML = S.icon('file', 24);
    const main = document.createElement('div'); main.style.minWidth = '0';
    const nm = document.createElement('div'); nm.className = 'nm'; nm.textContent = file.name;
    const sub = document.createElement('div'); sub.className = 'sub'; sub.textContent = `${S.formatBytes(file.size)}${file.size ? '' : ' (empty file)'} · ${file.type || 'unknown type'}`;
    main.append(nm, sub);
    const act = document.createElement('div'); act.className = 'act';
    const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'ibtn'; rm.innerHTML = S.icon('x', 17); rm.setAttribute('aria-label', 'Remove ' + file.name);
    rm.addEventListener('click', () => reset(false));
    act.appendChild(rm);
    el.file.append(th, main, act);
  }

  function setFile(f) {
    if (f.size > cfg.FILE_HASH_MAX_BYTES) { S.status(el.msg, 'bad', `That file is larger than ${S.formatBytes(cfg.FILE_HASH_MAX_BYTES)}.`); return; }
    if (thumbUrl) { URL.revokeObjectURL(thumbUrl); thumbUrl = null; }
    file = f; hex = ''; hexAlgo = '';
    if (S.isPreviewImage(f) && f.size <= cfg.PREVIEW_MAX_BYTES) thumbUrl = URL.createObjectURL(f);
    showFile(); compute();
  }

  async function compute() {
    if (!file) return;
    if (ctl) ctl.abort();
    const my = ++runId, algo = el.algo.value;
    ctl = new AbortController(); hex = ''; hexAlgo = '';
    el.computed.hidden = true; el.cancel.hidden = false; compare();
    S.status(el.msg, 'work', `Calculating ${algo}… 0%`);
    let paint = 0;
    try {
      const r = await H.hashBlob(file, algo, { signal: ctl.signal, thresholdBytes: cfg.STREAM_THRESHOLD_BYTES, workerUrl: cfg.WORKER_URL,
        onProgress: v => { const n = Date.now(); if (my === runId && (n - paint > 100 || v >= 1)) { paint = n; S.status(el.msg, 'work', `Calculating ${algo}… ${Math.round(v * 100)}%`); } } });
      if (my !== runId) return;
      hex = r.hex; hexAlgo = algo;
      el.algoOut.textContent = algo; el.hash.textContent = hex; el.computed.hidden = false;
      S.status(el.msg, 'ok', `${algo} calculated.`);
    } catch (e) {
      if (my !== runId) return;
      if (e && e.name === 'AbortError') S.status(el.msg, '', 'Cancelled.');
      else S.status(el.msg, 'bad', e && e.readError ? 'This file could not be read. It may be a folder, or it may have been moved or changed.' : 'Could not hash this file in this browser.');
    } finally { if (my === runId) { el.cancel.hidden = true; ctl = null; compare(); } }
  }

  function setVerdict(kind, title, text) {
    el.verdict.className = 'verdict' + (kind === 'waiting' ? '' : ' ' + kind) + (kind !== lastKind && kind !== 'waiting' ? ' pop' : '');
    lastKind = kind;
    el.verdict.querySelector('.vi').innerHTML = S.icon(kind === 'match' ? 'okc' : kind === 'mismatch' ? 'xc' : 'compare', 26);
    el.vt.textContent = title; el.vd.textContent = text;
  }

  function compare() {
    el.refMsg.textContent = ''; el.refMsg.className = 'status';
    const raw = el.ref.value;
    if (!raw.trim()) return setVerdict('waiting', 'WAITING', file ? 'Paste the reference hash to compare.' : 'Choose a file and paste a reference hash to compare.');
    const ref = H.normalizeReference(raw);
    if (!ref.ok) { S.status(el.refMsg, 'bad', 'That does not look like a hash. Use only the digits 0–9 and the letters a–f.'); return setVerdict('waiting', 'WAITING', 'Fix the reference hash to compare.'); }
    if (!ref.algo) { S.status(el.refMsg, 'bad', `A SHA-2 hash has 64, 96 or 128 characters. This one has ${ref.length}.`); return setVerdict('waiting', 'WAITING', 'The reference hash looks incomplete.'); }
    if (ref.algo !== el.algo.value) {
      S.status(el.refMsg, 'bad', `This looks like a ${ref.algo} hash, but ${el.algo.value} is selected.`);
      const b = document.createElement('button'); b.type = 'button'; b.className = 'btn sm'; b.textContent = `Switch to ${ref.algo}`; b.style.marginLeft = '10px';
      b.addEventListener('click', () => { el.algo.value = ref.algo; compute(); });
      el.refMsg.appendChild(b);
      return setVerdict('waiting', 'WAITING', 'The algorithms must be the same to compare.');
    }
    if (ref.note) S.status(el.refMsg, 'ok', ref.note);
    if (!file) return setVerdict('waiting', 'WAITING', 'Choose a file to compare.');
    if (!hex || hexAlgo !== ref.algo) return setVerdict('waiting', 'WAITING', 'Waiting for the file hash to finish…');
    if (hex === ref.hex) setVerdict('match', 'MATCH', 'The file’s bytes produce the reference hash. If you trust the source of that hash, the file is unchanged. This does not prove the file is safe.');
    else setVerdict('mismatch', 'MISMATCH', 'The hashes are different. The file may be changed or damaged, or the reference belongs to another file.');
  }

  function reset(clearRef) {
    runId++; if (ctl) ctl.abort(); ctl = null;
    if (thumbUrl) { URL.revokeObjectURL(thumbUrl); thumbUrl = null; }
    file = null; hex = ''; hexAlgo = '';
    el.computed.hidden = true; el.cancel.hidden = true; el.hash.textContent = '';
    S.status(el.msg, '', ''); showFile();
    if (clearRef) el.ref.value = '';
    compare();
  }

  el.browse.addEventListener('click', e => e.stopPropagation() || el.input.click());
  el.algo.addEventListener('change', () => { if (file) compute(); else compare(); });
  el.ref.addEventListener('input', compare);
  el.cancel.addEventListener('click', () => { if (ctl) ctl.abort(); });
  el.clear.addEventListener('click', () => reset(true));
  el.copy.addEventListener('click', async () => { if (hex) S.toast((await S.copyText(hex)) ? 'Computed hash copied.' : 'Could not copy. Select the hash and copy it manually.'); });
  addEventListener('pagehide', () => { if (thumbUrl) URL.revokeObjectURL(thumbUrl); });
  compare();
})();
