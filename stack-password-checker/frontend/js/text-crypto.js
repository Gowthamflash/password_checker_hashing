/* Text Encryption & Decryption page. All work is done locally with StackCrypto (Web Crypto API).
 * Nothing typed here is sent anywhere, stored, or written to the console. */
(() => {
  'use strict';
  const S = window.Stack, C = window.StackCrypto;
  const $ = s => document.querySelector(s);
  const el = {
    encIn: $('#encIn'), encPw: $('#encPw'), encPw2: $('#encPw2'), encBtn: $('#encBtn'), encClear: $('#encClear'), encMsg: $('#encMsg'),
    encResult: $('#encResult'), encOut: $('#encOut'), encInfo: $('#encInfo'), encCopy: $('#encCopy'), encDown: $('#encDown'),
    decIn: $('#decIn'), decPw: $('#decPw'), decBtn: $('#decBtn'), decClear: $('#decClear'), decMsg: $('#decMsg'),
    decResult: $('#decResult'), decOut: $('#decOut'), decCopy: $('#decCopy'), decDown: $('#decDown'),
    decLoad: $('#decLoad'), decFile: $('#decFile')
  };

  S.tabs(document.querySelector('.tablist'));
  document.querySelectorAll('[data-eye]').forEach(b => b.addEventListener('click', () => {
    const input = document.getElementById(b.dataset.eye);
    S.toggleEye(b, input);
    if (b.dataset.eye === 'encPw') el.encPw2.type = input.type;       // the eye shows or hides both fields
  }));

  const setBusy = (btn, busy, idle) => {
    btn.disabled = busy;
    btn.querySelector('span').textContent = busy ? 'Working…' : idle;
  };
  const safeMessage = (e, fallback) => (e && e.name === 'StackCryptoError') ? e.message : fallback;

  /* ----- encrypt ----- */
  async function encrypt() {
    const msg = el.encIn.value, pw = el.encPw.value;
    el.encResult.hidden = true; el.encOut.value = '';
    if (!msg) { S.status(el.encMsg, 'bad', 'Type a message to encrypt.'); el.encIn.focus(); return; }
    if (pw.length < C.MIN_PASSWORD) { S.status(el.encMsg, 'bad', `Use an encryption password of at least ${C.MIN_PASSWORD} characters.`); el.encPw.focus(); return; }
    if (pw !== el.encPw2.value) { S.status(el.encMsg, 'bad', 'The two passwords do not match.'); el.encPw2.focus(); return; }
    setBusy(el.encBtn, true, 'Encrypt');
    S.status(el.encMsg, 'work', 'Deriving the key and encrypting…');
    try {
      const out = await C.encryptText(msg, pw);
      el.encOut.value = out;
      el.encInfo.textContent = `${out.length.toLocaleString()} characters. AES-256-GCM, key from PBKDF2-SHA-256 (${C.ITER_DEFAULT.toLocaleString()} iterations). Keep your password: it cannot be recovered.`;
      el.encResult.hidden = false;
      S.status(el.encMsg, 'ok', 'Encrypted. Copy or download the output below.');
    } catch (e) {
      S.status(el.encMsg, 'bad', safeMessage(e, 'Encryption failed in this browser.'));
    } finally { setBusy(el.encBtn, false, 'Encrypt'); }
  }
  function clearEnc() {
    el.encIn.value = el.encPw.value = el.encPw2.value = el.encOut.value = '';
    el.encResult.hidden = true; S.status(el.encMsg, '', '');
  }
  el.encBtn.addEventListener('click', encrypt);
  el.encClear.addEventListener('click', () => { clearEnc(); el.encIn.focus(); });
  el.encCopy.addEventListener('click', async () => S.toast((await S.copyText(el.encOut.value)) ? 'Encrypted output copied.' : 'Could not copy. Select the text and copy it manually.'));
  el.encDown.addEventListener('click', () => { S.downloadText(el.encOut.value + '\n', 'encrypted-message.txt'); S.toast('Download started.'); });
  el.encPw2.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); encrypt(); } });

  /* ----- decrypt ----- */
  async function decrypt() {
    el.decResult.hidden = true; el.decOut.value = '';
    if (!el.decIn.value.trim()) { S.status(el.decMsg, 'bad', 'Paste the encrypted text first.'); el.decIn.focus(); return; }
    if (!el.decPw.value) { S.status(el.decMsg, 'bad', 'Enter the encryption password.'); el.decPw.focus(); return; }
    setBusy(el.decBtn, true, 'Decrypt');
    S.status(el.decMsg, 'work', 'Deriving the key and decrypting…');
    try {
      el.decOut.value = await C.decryptText(el.decIn.value, el.decPw.value);
      el.decResult.hidden = false;
      S.status(el.decMsg, 'ok', 'Decrypted successfully. The message was not modified.');
    } catch (e) {
      S.status(el.decMsg, 'bad', safeMessage(e, 'Decryption failed in this browser.'));
    } finally { setBusy(el.decBtn, false, 'Decrypt'); }
  }
  function clearDec() {
    el.decIn.value = el.decPw.value = el.decOut.value = '';
    el.decResult.hidden = true; S.status(el.decMsg, '', '');
  }
  el.decBtn.addEventListener('click', decrypt);
  el.decClear.addEventListener('click', () => { clearDec(); el.decIn.focus(); });
  el.decCopy.addEventListener('click', async () => S.toast((await S.copyText(el.decOut.value)) ? 'Message copied.' : 'Could not copy. Select the text and copy it manually.'));
  el.decDown.addEventListener('click', () => { S.downloadText(el.decOut.value, 'decrypted-message.txt'); S.toast('Download started.'); });
  el.decPw.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); decrypt(); } });
  el.decLoad.addEventListener('click', () => el.decFile.click());
  el.decFile.addEventListener('change', async () => {
    const f = el.decFile.files[0]; el.decFile.value = '';
    if (!f) return;
    if (f.size > 12 * 1024 * 1024) { S.status(el.decMsg, 'bad', 'That file is too large to be an encrypted message.'); return; }
    try { el.decIn.value = await f.text(); S.status(el.decMsg, '', ''); el.decResult.hidden = true; el.decPw.focus(); }
    catch (e) { S.status(el.decMsg, 'bad', 'That file could not be read.'); }
  });

  // never leave secrets sitting in a page restored from the back/forward cache
  addEventListener('pageshow', e => { if (e.persisted) { clearEnc(); clearDec(); } });

  if (!(window.crypto && window.crypto.subtle)) {
    const msg = 'Encryption needs the Web Crypto API. Open this page over HTTPS or on localhost, in an up-to-date browser.';
    S.status(el.encMsg, 'bad', msg); S.status(el.decMsg, 'bad', msg);
    [el.encBtn, el.decBtn].forEach(b => { b.disabled = true; });
  }
})();
