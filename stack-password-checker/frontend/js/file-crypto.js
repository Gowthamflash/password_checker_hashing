/* File Encryption & Decryption page. Files are encrypted/decrypted entirely in the browser (AES-256-GCM).
 * Files, passwords and keys are never uploaded, stored or logged. Decrypted files are never opened or previewed. */
(() => {
  'use strict';
  const S = window.Stack, C = window.StackCrypto, H = window.StackHash, cfg = S.cfg();
  const $ = s => document.querySelector(s);
  const MAX = cfg.FILE_ENCRYPT_MAX_BYTES, OVERHEAD = 64 * 1024;       // encrypted files are slightly larger than the original
  document.querySelectorAll('.maxInfo').forEach(n => { n.textContent = S.formatBytes(MAX); });
  S.tabs(document.querySelector('.tablist'));
  document.querySelectorAll('[data-eye]').forEach(b => b.addEventListener('click', () => {
    const input = document.getElementById(b.dataset.eye);
    S.toggleEye(b, input);
    if (b.dataset.eye === 'fePw') $('#fePw2').type = input.type;
  }));
  const safeMessage = (e, fallback) => (e && e.name === 'StackCryptoError') ? e.message : fallback;
  const setBusy = (btn, busy, idle) => { btn.querySelector('span').textContent = busy ? 'Working…' : idle; };

  function selectionCard(box, file, onRemove) {
    box.textContent = ''; box.hidden = !file; if (!file) return;
    const th = document.createElement('div'); th.className = 'th'; th.innerHTML = S.icon('file', 24);
    const main = document.createElement('div'); main.style.minWidth = '0';
    const nm = document.createElement('div'); nm.className = 'nm'; nm.textContent = file.name;
    const sub = document.createElement('div'); sub.className = 'sub'; sub.textContent = `${S.formatBytes(file.size)} · ${file.type || 'unknown type'}`;
    main.append(nm, sub);
    const act = document.createElement('div'); act.className = 'act';
    const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'ibtn'; rm.innerHTML = S.icon('x', 17); rm.setAttribute('aria-label', 'Remove ' + file.name);
    rm.addEventListener('click', onRemove); act.appendChild(rm);
    box.append(th, main, act);
  }

  /* ================= encrypt ================= */
  const enc = { file: null, blob: null, name: '' };
  const e = { drop: $('#dropEnc'), browse: $('#browseEnc'), input: $('#encFileIn'), sel: $('#encSel'), pw: $('#fePw'), pw2: $('#fePw2'),
    btn: $('#feBtn'), clear: $('#feClear'), msg: $('#feMsg'), result: $('#feResult'), name: $('#feName'), size: $('#feSize'), down: $('#feDown') };

  function encUpdate() { e.btn.disabled = !enc.file; }
  function encDropResult() { enc.blob = null; e.result.hidden = true; }
  function encSetFile(f) {
    if (f.size > MAX) { S.status(e.msg, 'bad', `That file is ${S.formatBytes(f.size)}. This tool encrypts files up to ${S.formatBytes(MAX)} because the whole file is processed in memory.`); return; }
    enc.file = f; encDropResult(); S.status(e.msg, '', '');
    selectionCard(e.sel, f, () => { enc.file = null; selectionCard(e.sel, null); encDropResult(); encUpdate(); });
    encUpdate();
  }
  S.dropzone(e.drop, e.input, files => { if (files[0]) encSetFile(files[0]); });
  e.browse.addEventListener('click', ev => ev.stopPropagation() || e.input.click());

  async function encrypt() {
    if (!enc.file) { S.status(e.msg, 'bad', 'Choose a file first.'); return; }
    const pw = e.pw.value;
    if (pw.length < C.MIN_PASSWORD) { S.status(e.msg, 'bad', `Use an encryption password of at least ${C.MIN_PASSWORD} characters.`); e.pw.focus(); return; }
    if (pw !== e.pw2.value) { S.status(e.msg, 'bad', 'The two passwords do not match.'); e.pw2.focus(); return; }
    encDropResult(); e.btn.disabled = true; setBusy(e.btn, true, 'Encrypt file');
    S.status(e.msg, 'work', 'Reading the file, deriving the key and encrypting…');
    try {
      const f = enc.file;
      const bytes = new Uint8Array(await f.arrayBuffer());
      const blob = await C.encryptFile(bytes, { name: f.name, type: f.type, lastModified: f.lastModified }, pw);
      bytes.fill(0);
      enc.blob = blob; enc.name = S.safeFilename(f.name, 'file') + '.stackenc';
      e.name.textContent = enc.name; e.size.textContent = S.formatBytes(blob.size);
      e.result.hidden = false;
      S.status(e.msg, 'ok', 'Encrypted. Download the file below and keep your password safe.');
    } catch (err) {
      const mem = err && (err.name === 'RangeError' || err.name === 'QuotaExceededError');
      const read = err && (err.name === 'NotReadableError' || err.name === 'NotFoundError');
      S.status(e.msg, 'bad', mem ? 'This device ran out of memory. Try a smaller file.' : read ? 'This file could not be read. It may have been moved or changed.' : safeMessage(err, 'Encryption failed in this browser.'));
    } finally { setBusy(e.btn, false, 'Encrypt file'); encUpdate(); }
  }
  e.btn.addEventListener('click', encrypt);
  e.down.addEventListener('click', () => { if (enc.blob) { S.downloadBlob(enc.blob, enc.name); S.toast('Download started.'); } });
  function encClear() {
    enc.file = null; encDropResult(); selectionCard(e.sel, null); e.pw.value = e.pw2.value = ''; S.status(e.msg, '', ''); encUpdate();
  }
  e.clear.addEventListener('click', encClear);

  /* ================= decrypt ================= */
  const dec = { file: null, blob: null, name: '' };
  const d = { drop: $('#dropDec'), browse: $('#browseDec'), input: $('#decFileIn'), sel: $('#decSel'), pw: $('#fdPw'),
    btn: $('#fdBtn'), clear: $('#fdClear'), msg: $('#fdMsg'), result: $('#fdResult'), name: $('#fdName'), type: $('#fdType'),
    size: $('#fdSize'), hash: $('#fdHash'), down: $('#fdDown') };

  function decUpdate() { d.btn.disabled = !dec.file; }
  function decDropResult() { dec.blob = null; d.result.hidden = true; d.hash.textContent = ''; }
  function decSetFile(f) {
    if (f.size > MAX + OVERHEAD) { S.status(d.msg, 'bad', `That file is larger than this tool can open (${S.formatBytes(MAX + OVERHEAD)}).`); return; }
    dec.file = f; decDropResult(); S.status(d.msg, '', '');
    selectionCard(d.sel, f, () => { dec.file = null; selectionCard(d.sel, null); decDropResult(); decUpdate(); });
    decUpdate();
  }
  S.dropzone(d.drop, d.input, files => { if (files[0]) decSetFile(files[0]); });
  d.browse.addEventListener('click', ev => ev.stopPropagation() || d.input.click());

  async function decrypt() {
    if (!dec.file) { S.status(d.msg, 'bad', 'Choose an encrypted file first.'); return; }
    if (!d.pw.value) { S.status(d.msg, 'bad', 'Enter the encryption password.'); d.pw.focus(); return; }
    decDropResult(); d.btn.disabled = true; setBusy(d.btn, true, 'Decrypt file');
    S.status(d.msg, 'work', 'Reading the file, deriving the key and decrypting…');
    try {
      const bytes = new Uint8Array(await dec.file.arrayBuffer());
      const out = await C.decryptFile(bytes, d.pw.value);
      // octet-stream on purpose: the recovered file is saved, never rendered or executed by the browser
      dec.blob = new Blob([out.data], { type: 'application/octet-stream' });
      dec.name = S.safeFilename(out.name, 'recovered-file');
      d.name.textContent = out.name; d.type.textContent = out.type || 'unknown'; d.size.textContent = S.formatBytes(out.size);
      d.hash.textContent = await H.digestBytes('SHA-256', out.data);
      d.result.hidden = false;
      S.status(d.msg, 'ok', 'Decrypted successfully. The file passed the integrity check.');
    } catch (err) {
      const mem = err && (err.name === 'RangeError' || err.name === 'QuotaExceededError');
      const read = err && (err.name === 'NotReadableError' || err.name === 'NotFoundError');
      S.status(d.msg, 'bad', mem ? 'This device ran out of memory. Try a smaller file.' : read ? 'This file could not be read. It may have been moved or changed.' : safeMessage(err, 'Decryption failed in this browser.'));
    } finally { setBusy(d.btn, false, 'Decrypt file'); decUpdate(); }
  }
  d.btn.addEventListener('click', decrypt);
  d.pw.addEventListener('keydown', ev => { if (ev.key === 'Enter') { ev.preventDefault(); decrypt(); } });
  d.down.addEventListener('click', () => { if (dec.blob) { S.downloadBlob(dec.blob, dec.name); S.toast('Download started.'); } });
  function decClear() { dec.file = null; decDropResult(); selectionCard(d.sel, null); d.pw.value = ''; S.status(d.msg, '', ''); decUpdate(); }
  d.clear.addEventListener('click', decClear);

  addEventListener('pageshow', ev => { if (ev.persisted) { encClear(); decClear(); } });

  if (!(window.crypto && window.crypto.subtle)) {
    const msg = 'Encryption needs the Web Crypto API. Open this page over HTTPS or on localhost, in an up-to-date browser.';
    S.status(e.msg, 'bad', msg); S.status(d.msg, 'bad', msg);
    e.btn.disabled = d.btn.disabled = true;
  }
  encUpdate(); decUpdate();
})();
