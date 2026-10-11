/* Stack Password Checker
 * - Passwords are analyzed in the browser and are never sent to the backend.
 * - The only network calls are history summaries to /api/history (see js/config.js).
 * - The shared header, footer, theme toggle and icons live in js/common.js.
 * - The password itself is never written to storage, logged, or copied into a variable.
 * - History stores only: id, time, strength level, score, checks passed, length
 * (in the Python backend's SQLite database when available, otherwise in localStorage).
 */
(() => {
  'use strict';

  /*ANALYZER_START*/
  const COMMON = new Set(('password,123456,12345678,123456789,qwerty,abc123,letmein,monkey,dragon,football,iloveyou,admin,welcome,login,' +
    'princess,sunshine,master,shadow,superman,trustno1,baseball,passw0rd,whatever,hello,freedom,starwars,batman,access,flower,111111,000000,' +
    '123123,654321,1q2w3e4r,qazwsx,zaq12wsx,michael,jordan,harley,hunter,ranger,soccer,summer,winter,spring,autumn,secret,changeme,welcome1,' +
    'pokemon,cookie,charlie,mustang,computer,internet,test,guest,root,pass,stack,qwertyuiop,asdfghjkl,iloveu,biteme,lovely,ashley,bailey').split(','));
  const LEET = { '@': 'a', '4': 'a', '0': 'o', '3': 'e', '$': 's', '5': 's', '7': 't', '1': 'i', '!': 'i' };
  const ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];

  function isCommon(pw) {
    const lower = pw.toLowerCase();
    const leet = [...lower].map(c => LEET[c] || c).join('');
    const trim = s => s.replace(/[^a-z]+$/, '').replace(/^[^a-z]+/, '');
    return [lower, leet, trim(lower), trim(leet)].some(s => s && COMMON.has(s));
  }
  function hasSequence(pw) {
    const s = pw.toLowerCase();
    for (let i = 0; i < s.length - 2; i++) {
      const a = s.charCodeAt(i), b = s.charCodeAt(i + 1), c = s.charCodeAt(i + 2);
      if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) return true;
    }
    return ROWS.some(r => {
      for (let i = 0; i <= r.length - 4; i++) {
        const w = r.slice(i, i + 4);
        if (s.includes(w) || s.includes([...w].reverse().join(''))) return true;
      }
      return false;
    });
  }
  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }
  function guessTime(bits) {
    const sec = Math.pow(2, bits) / 2 / 1e10;
    if (sec < 1) return 'under a second';
    if (sec < 60) return plural(Math.round(sec), 'second');
    const min = sec / 60; if (min < 60) return plural(Math.round(min), 'minute');
    const h = min / 60; if (h < 24) return plural(Math.round(h), 'hour');
    const d = h / 24; if (d < 30) return plural(Math.round(d), 'day');
    if (d < 365) return plural(Math.round(d / 30.44), 'month');
    const y = d / 365.25;
    if (y < 100) return plural(Math.round(y), 'year');
    if (y < 1e3) return 'centuries';
    if (y < 1e6) return 'thousands of years';
    if (y < 1e9) return 'millions of years';
    return 'billions of years';
  }

  function analyze(pw) {
    const chars = [...pw], len = chars.length;
    const has = {
      upper: /\p{Lu}/u.test(pw),
      lower: /\p{Ll}/u.test(pw),
      num: /\p{Nd}/u.test(pw),
      special: /[^\p{L}\p{N}]/u.test(pw)
    };
    const checks = [len >= 12, has.upper, has.lower, has.num, has.special];
    const passed = checks.filter(Boolean).length;
    const classes = [has.upper, has.lower, has.num, has.special].filter(Boolean).length;
    if (!len) return { len: 0, score: 0, level: 'none', label: '—', checks, passed: 0, classes: 0, has, warn: [], bits: 0, time: '—' };

    const warn = [];
    if (isCommon(pw)) warn.push('common');
    if (/(.)\1{2,}/u.test(pw)) warn.push('repeat');
    if (hasSequence(pw)) warn.push('seq');
    if (/(19|20)\d{2}$/.test(pw)) warn.push('year');
    if (/^(.{2,6})\1{1,}$/u.test(pw)) warn.push('block');

    const uniq = new Set(chars).size;
    let score = passed * 12 + Math.min(30, Math.max(0, len - 4) * 2.5) + Math.min(10, (uniq / len) * 10);
    if (warn.includes('repeat')) score -= 10;
    if (warn.includes('seq')) score -= 10;
    if (warn.includes('year')) score -= 8;
    if (warn.includes('block')) score -= 25;
    if (uniq === 1) score = Math.min(score, 5);
    if (warn.includes('common')) score = Math.min(score, 12);
    if (len < 8) score = Math.min(score, 39);
    if (passed < 5) score = Math.min(score, 74);
    score = Math.max(0, Math.min(100, Math.round(score)));

    const level = score < 40 ? 'weak' : score < 75 ? 'medium' : 'strong';
    const pool = (has.lower ? 26 : 0) + (has.upper ? 26 : 0) + (has.num ? 10 : 0) + (has.special ? 33 : 0) || 10;
    let bits = len * Math.log2(pool);
    if (warn.includes('common')) bits = Math.min(bits, 14);
    else if (warn.length) bits *= 0.75;
    bits = Math.round(bits);

    return { len, score, level, label: level.toUpperCase(), checks, passed, classes, has, warn, bits, time: guessTime(bits) };
  }
  /*ANALYZER_END*/

  /* ---------- helpers ---------- */
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const icon = (n, s = 18) => `<svg class="i" width="${s}" height="${s}" aria-hidden="true"><use href="#i-${n}"/></svg>`;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  const store = (() => {
    try { const k = '__t'; localStorage.setItem(k, '1'); localStorage.removeItem(k); return localStorage; }
    catch (e) { const m = {}; return { getItem: k => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); } }; }
  })();
  const KEY_H = 'stack-pc:history';

  const el = {
    app: $('#app'), loader: $('#loader'), pw: $('#pw'), field: $('#field'), msg: $('#pwMsg'), eye: $('#eye'),
    analyze: $('#analyze'), reset: $('#reset'), checker: $('#checker'), strLabel: $('#strLabel'), strPct: $('#strPct'),
    meter: $('#meter'), live: $('#liveStatus'), checks: $$('#checks .chk'), report: $('#report'), repTag: $('#repTag'),
    wait: $('#reportWait'), waitTitle: $('#waitTitle'), waitText: $('#waitText'), body: $('#reportBody'),
    ring: $('#ring'), ringFg: $('#ringFg'), ringN: $('#ringN'), recs: $('#recs'),
    histList: $('#histList'), histEmpty: $('#histEmpty'), clearAll: $('#clearAll'),
    dlg: $('#confirm'), cT: $('#cT'), cD: $('#cD'), cOk: $('#cOk'), cNo: $('#cNo'), toast: $('#toast'),
    tLen: $('#tLen'), tCls: $('#tCls')
  };
  const segs = $$('.seg', el.meter);
  const RING_C = 339.3;
  let dirty = true, analyzed = false, lastLevel = '';

  function setLv(node, lv) {
    node.classList.remove('lv-none', 'lv-weak', 'lv-medium', 'lv-strong');
    node.classList.add('lv-' + lv);
  }
  const raf = new WeakMap();
  function tween(node, to, d = 450) {
    const from = +node.dataset.v || 0;
    node.dataset.v = to;
    cancelAnimationFrame(raf.get(node));
    if (reduced || from === to) { node.textContent = to; return; }
    const t0 = performance.now();
    const step = t => {
      const p = Math.min(1, (t - t0) / d);
      node.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3)));
      if (p < 1) raf.set(node, requestAnimationFrame(step));
    };
    raf.set(node, requestAnimationFrame(step));
  }
  let toastT;
  function toast(m) {
    el.toast.textContent = m; el.toast.classList.add('show');
    clearTimeout(toastT); toastT = setTimeout(() => el.toast.classList.remove('show'), 2600);
  }

  /* ---------- live analysis ---------- */
  function renderLive(a) {
    const has = el.pw.value.length > 0;
    const lv = has ? a.level : 'none';
    setLv(el.checker, lv);
    el.strLabel.textContent = has ? a.label : 'Waiting…';
    tween(el.strPct, a.score);
    const n = Math.round(a.score / 5);
    segs.forEach((s, i) => s.classList.toggle('on', i < n));
    el.meter.setAttribute('aria-valuenow', a.score);
    el.checks.forEach((li, i) => {
      const st = !has ? 'pend' : a.checks[i] ? 'ok' : 'no';
      if (li.dataset.s === st) return;
      li.dataset.s = st;
      li.className = 'chk ' + st;
      li.firstElementChild.innerHTML = st === 'ok' ? icon('check', 15) : st === 'no' ? icon('x', 14) : icon('check', 13);
      li.lastElementChild.textContent = st === 'ok' ? 'Passed' : st === 'no' ? 'Not satisfied' : 'Pending';
    });
    el.tLen.textContent = has ? a.len : 'waiting';
    el.tCls.textContent = has ? a.classes + ' of 4' : 'waiting';
    if (lv !== lastLevel) {
      lastLevel = lv;
      el.live.textContent = has ? `Password strength: ${a.label.toLowerCase()}, score ${a.score} percent.` : '';
    }
  }

  /* ---------- report + recommendations ---------- */
  const SUMMARY = {
    strong: 'Resistant to guessing and common attack patterns.',
    medium: 'A decent start, but a few gaps remain.',
    weak: 'Easy to guess. Change this password before using it.'
  };
  const REC = [
    'Use at least 12 characters.', 'Add at least one uppercase letter.', 'Add at least one lowercase letter.',
    'Add at least one number.', 'Add at least one special character, such as ! @ # or $.'
  ];
  const WARN = {
    common: 'This looks like a commonly used password. Choose something less predictable.',
    repeat: 'Avoid repeating the same character three or more times in a row.',
    seq: 'Avoid simple sequences such as 123, abc or qwerty.',
    year: 'Avoid ending your password with a year. It is one of the first things attackers try.',
    block: 'Avoid repeating the same short group of characters over and over.'
  };
  function yn(node, ok, yes, no) {
    node.className = 'v ' + (ok ? 'y' : 'n');
    node.innerHTML = icon(ok ? 'check' : 'x', 15) + (ok ? yes : no);
  }
  function showReport(a) {
    setLv(el.report, a.level);
    el.wait.hidden = true; el.body.hidden = false; el.repTag.hidden = false;
    $('#repLabel').textContent = a.label;
    $('#repSum').textContent = SUMMARY[a.level];
    const sS = $('#sStrength'); sS.textContent = a.label; sS.style.color = 'var(--lv)';
    $('#sScore').textContent = a.score + ' / 100';
    $('#sLen').textContent = a.len + (a.len === 1 ? ' character' : ' characters');
    yn($('#sUp'), a.has.upper, 'Detected', 'Missing');
    yn($('#sLow'), a.has.lower, 'Detected', 'Missing');
    yn($('#sNum'), a.has.num, 'Detected', 'Missing');
    yn($('#sSpec'), a.has.special, 'Detected', 'Missing');
    $('#trCls').textContent = a.classes + ' of 4';
    $('#trBits').textContent = '~' + a.bits + ' bits';
    $('#trTime').textContent = a.time;
    el.ring.setAttribute('aria-label', `Security score ${a.score} out of 100`);
    el.ringN.dataset.v = 0; el.ringN.textContent = 0;
    el.ringFg.style.transition = 'none';
    el.ringFg.style.strokeDashoffset = RING_C;
    void el.ringFg.getBoundingClientRect();
    el.ringFg.style.transition = '';
    el.ringFg.style.strokeDashoffset = (RING_C * (1 - a.score / 100)).toFixed(1);
    tween(el.ringN, a.score, 900);
    el.body.classList.remove('reveal'); void el.body.offsetWidth; el.body.classList.add('reveal');
  }
  function hideReport(title, text) {
    setLv(el.report, 'none');
    el.body.hidden = true; el.repTag.hidden = true; el.wait.hidden = false;
    el.waitTitle.textContent = title; el.waitText.textContent = text;
  }
  function renderRecs(a) {
    if (!a) {
      el.recs.innerHTML = `<li class="idle">${icon('bulb', 18)}<span>Recommendations appear here after you analyze a password.</span></li>`;
      return;
    }
    const items = a.checks.map((ok, i) => ok ? null : REC[i]).filter(Boolean).concat(a.warn.map(k => WARN[k]));
    el.recs.innerHTML = items.length
      ? items.map(t => `<li>${icon('alert', 18)}<span>${t}</span></li>`).join('')
      : `<li class="good">${icon('shieldchk', 18)}<span>Excellent! Your password meets all basic requirements.</span></li>`;
  }

  /* ---------- input actions ---------- */
  function clearErr() { el.field.classList.remove('err'); el.msg.textContent = ''; }
  function onInput() {
    dirty = true; clearErr();
    renderLive(analyze(el.pw.value));
    if (analyzed) {
      analyzed = false;
      hideReport('Ready to analyze', 'Press “Analyze Password” to update the report.');
      renderRecs(null);
    } else if (!el.pw.value) {
      hideReport('No password analyzed yet', 'Type a password to see a live score, then press “Analyze Password”.');
    }
  }
  function doAnalyze() {
    const v = el.pw.value;
    if (!v) {
      el.field.classList.add('err'); el.msg.textContent = 'Enter a password to analyze.';
      el.field.classList.remove('shake'); void el.field.offsetWidth; el.field.classList.add('shake');
      el.pw.focus(); return;
    }
    clearErr();
    const a = analyze(v);
    renderLive(a); showReport(a); renderRecs(a);
    if (dirty || !analyzed) { addHistory(a); toast('Analysis complete. Only a summary was saved.'); }
    dirty = false; analyzed = true;
    if (matchMedia('(max-width: 860px)').matches) el.report.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
  }
  function doReset() {
    el.pw.value = ''; el.pw.type = 'password';
    el.eye.innerHTML = icon('eye', 20); el.eye.setAttribute('aria-label', 'Show password'); el.eye.setAttribute('aria-pressed', 'false');
    dirty = true; analyzed = false; clearErr();
    renderLive(analyze('')); hideReport('No password analyzed yet', 'Type a password to see a live score, then press “Analyze Password”.'); renderRecs(null);
    el.checker.classList.remove('flash'); void el.checker.offsetWidth; el.checker.classList.add('flash');
    toast('Analyzer reset. Your history was kept.');
    el.pw.focus();
  }
  function toggleEye() {
    const show = el.pw.type === 'password';
    el.pw.type = show ? 'text' : 'password';
    el.eye.innerHTML = icon(show ? 'eyeoff' : 'eye', 20);
    el.eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    el.eye.setAttribute('aria-pressed', String(show));
    el.pw.focus();
  }

  /* ---------- history (Python backend with localStorage fallback) ---------- */
  const CFG = Object.assign({ API_BASE: '/api', HISTORY_MODE: 'auto', MAX_HISTORY: 30 }, window.STACK_CONFIG || {});
  const LEVELS = { weak: 'WEAK', medium: 'MEDIUM', strong: 'STRONG' };
  let mode = 'local';           // 'server' | 'local'
  let history = [];

  // Accept only well-formed summary records (from the server or from localStorage).
  function sanitize(h) {
    if (!h || !LEVELS[h.level]) return null;
    const length = h.length !== undefined ? h.length : h.len;   // 'len' = records saved by older versions
    if (![h.ts, h.score, h.passed, length].every(Number.isFinite)) return null;
    return { id: String(h.id), ts: h.ts, level: h.level, score: h.score, passed: h.passed, length };
  }
  const localStore = {
    load() {
      try {
        const raw = JSON.parse(store.getItem(KEY_H) || '[]');
        return Array.isArray(raw) ? raw.map(sanitize).filter(Boolean) : [];
      } catch (e) { return []; }
    },
    save(list) { try { store.setItem(KEY_H, JSON.stringify(list)); } catch (e) { /* storage full or blocked */ } }
  };
  async function api(path, opts = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    try {
      const headers = opts.body ? { 'Content-Type': 'application/json' } : {};
      const r = await fetch(CFG.API_BASE + path, Object.assign({ credentials: 'same-origin', headers, signal: ctrl.signal }, opts));
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.status === 204 ? null : await r.json();
    } finally { clearTimeout(timer); }
  }
  function updateNote() {
    $('#histNote').textContent = mode === 'server'
      ? 'Only strength, score, length and time are kept, in the server database. Your password is never sent or saved.'
      : 'Only strength, score, length and time are kept, in this browser. Your password is never saved.';
  }
  async function initHistory() {
    if (CFG.HISTORY_MODE !== 'local' && location.protocol !== 'file:') {
      try {
        const d = await api('/history');
        history = (d.items || []).map(sanitize).filter(Boolean);
        mode = 'server';
      } catch (e) {
        if (CFG.HISTORY_MODE === 'server') toast('Backend not reachable. Showing this browser’s history.');
      }
    }
    if (mode === 'local') history = localStore.load();
    renderHistory(); updateNote();
  }
  async function addHistory(a) {
    const payload = { level: a.level, score: a.score, passed: a.passed, length: a.len };   // summary only
    let rec = null;
    if (mode === 'server') {
      try { rec = sanitize((await api('/history', { method: 'POST', body: JSON.stringify(payload) })).item); }
      catch (e) {
        mode = 'local'; history = localStore.load(); updateNote();
        toast('Backend unreachable. Saving this summary in your browser instead.');
      }
    }
    if (!rec) rec = Object.assign({ id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), ts: Date.now() }, payload);
    history.unshift(rec);
    history = history.slice(0, CFG.MAX_HISTORY);
    if (mode === 'local') localStore.save(history);
    renderHistory(rec.id);
  }
  async function removeRecord(id) {
    if (mode === 'server') {
      try { await api('/history/' + encodeURIComponent(id), { method: 'DELETE' }); }
      catch (e) { toast('Could not delete that record on the server.'); return false; }
    }
    history = history.filter(h => h.id !== id);
    if (mode === 'local') localStore.save(history);
    return true;
  }
  async function clearRecords() {
    if (mode === 'server') {
      try { await api('/history', { method: 'DELETE' }); }
      catch (e) { toast('Could not clear history on the server.'); return false; }
    }
    history = [];
    if (mode === 'local') localStore.save(history);
    return true;
  }
  function fmtTime(ts) {
    const d = new Date(ts), t = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    return d.toDateString() === new Date().toDateString() ? t : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ', ' + t;
  }
  function renderHistory(newId) {
    el.histList.innerHTML = history.map(h => {
      const lbl = LEVELS[h.level];
      return `<li class="hr lv-${h.level}${h.id === newId ? ' new' : ''}" data-id="${h.id.replace(/[^\w-]/g, '')}">
        <span class="pill">${lbl}</span><span class="sc">${h.passed}/5</span>
        <span class="ln">${h.length} ${h.length === 1 ? 'character' : 'characters'}</span>
        <span class="tm" title="Score ${h.score}/100">${fmtTime(h.ts)}</span>
        <button class="ibtn" type="button" data-del="${h.id.replace(/[^\w-]/g, '')}" aria-label="Delete ${lbl.toLowerCase()} analysis from ${fmtTime(h.ts)}">${icon('trash', 17)}</button></li>`;
    }).join('');
    el.histEmpty.hidden = history.length > 0;
    el.clearAll.disabled = history.length === 0;
  }

  let pending = null;
  function confirmDialog(cfg) {
    pending = cfg;
    if (typeof el.dlg.showModal !== 'function') {
      if (window.confirm(cfg.title + '\n' + cfg.text)) cfg.run();
      return;
    }
    el.cT.textContent = cfg.title; el.cD.textContent = cfg.text; el.cOk.textContent = cfg.ok;
    el.dlg.returnValue = 'cancel';
    el.dlg.showModal();
  }
  el.dlg.addEventListener('close', () => {
    $$('.hr.target').forEach(r => r.classList.remove('target'));
    const run = pending; pending = null;
    if (run && el.dlg.returnValue === 'confirm') run.run();
  });
  el.dlg.addEventListener('click', e => { if (e.target === el.dlg) el.dlg.close('cancel'); });

  el.histList.addEventListener('click', e => {
    const b = e.target.closest('[data-del]'); if (!b) return;
    const id = b.dataset.del, row = b.closest('.hr'), rec = history.find(h => h.id === id); if (!rec) return;
    row.classList.add('target');
    confirmDialog({
      title: 'Delete this record?',
      text: `Removes the “${rec.level}, ${rec.length} ${rec.length === 1 ? 'character' : 'characters'}” entry. Only a summary is deleted. No password was ever saved.`,
      ok: 'Delete record',
      run: () => {
        row.classList.remove('target'); row.classList.add('removing');
        setTimeout(async () => { const ok = await removeRecord(id); renderHistory(); if (ok) toast('Record deleted.'); }, reduced ? 0 : 300);
      }
    });
  });
  el.clearAll.addEventListener('click', () => {
    if (!history.length) return;
    confirmDialog({
      title: 'Clear all history?',
      text: `This removes all ${history.length} saved ${history.length === 1 ? 'summary' : 'summaries'} from this device. This cannot be undone.`,
      ok: 'Clear history',
      run: () => {
        $$('.hr').forEach(r => r.classList.add('removing'));
        setTimeout(async () => { const ok = await clearRecords(); renderHistory(); if (ok) toast('History cleared.'); }, reduced ? 0 : 320);
      }
    });
  });


  /* ---------- password generator (browser only, crypto.getRandomValues) ---------- */
  const GEN = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower: 'abcdefghijklmnopqrstuvwxyz',
    num: '0123456789', sym: '!@#$%^&*()-_=+[]{};:,.?/~'
  };
  const gel = {
    out: $('#genOut'), meta: $('#genMeta'), len: $('#genLen'), lenVal: $('#genLenVal'), gen: $('#genBtn'), copy: $('#genCopy'), use: $('#genUse'),
    boxes: { upper: $('#gUpper'), lower: $('#gLower'), num: $('#gNum'), sym: $('#gSym') }, amb: $('#gAmb')
  };
  function randInt(max) {                     // unbiased (rejection sampling)
    const lim = Math.floor(0x100000000 / max) * max, a = new Uint32Array(1);
    do { crypto.getRandomValues(a); } while (a[0] >= lim);
    return a[0] % max;
  }
  function makePassword(len, types, avoidAmbiguous) {
    const sets = types.map(t => avoidAmbiguous ? GEN[t].replace(/[0O1lI]/g, '') : GEN[t]);
    const pool = sets.join('');
    const pw = sets.map(set => set[randInt(set.length)]);          // at least one of every selected type
    while (pw.length < len) pw.push(pool[randInt(pool.length)]);
    for (let i = pw.length - 1; i > 0; i--) { const j = randInt(i + 1); [pw[i], pw[j]] = [pw[j], pw[i]]; }
    return { text: pw.join(''), poolSize: pool.length };
  }
  function selectedTypes() { return Object.keys(gel.boxes).filter(k => gel.boxes[k].checked); }
  function generate() {
    if (!window.crypto || !crypto.getRandomValues) { gel.meta.textContent = 'This browser cannot generate secure random values.'; return; }
    let types = selectedTypes();
    if (!types.length) { gel.boxes.lower.checked = true; types = ['lower']; }
    const len = +gel.len.value;
    const r = makePassword(len, types, gel.amb.checked);
    gel.out.value = r.text;
    const bits = Math.floor(len * Math.log2(r.poolSize));
    gel.meta.textContent = `${len} characters from a pool of ${r.poolSize}: about ${bits} bits of randomness.`;
  }
  gel.len.addEventListener('input', () => { gel.lenVal.textContent = gel.len.value; generate(); });
  Object.values(gel.boxes).concat(gel.amb).forEach(b => b.addEventListener('change', () => {
    if (!selectedTypes().length) b.checked = true;               // keep at least one character type on
    generate();
  }));
  gel.gen.addEventListener('click', generate);
  gel.copy.addEventListener('click', async () => {
    if (!gel.out.value) generate();
    const ok = await window.Stack.copyText(gel.out.value);
    toast(ok ? 'Copied. Save it in a password manager, then clear your clipboard.' : 'Could not copy. Select the text and copy it manually.');
  });
  gel.use.addEventListener('click', () => {
    if (!gel.out.value) generate();
    el.pw.value = gel.out.value; el.pw.type = 'password';
    el.eye.innerHTML = icon('eye', 20); el.eye.setAttribute('aria-label', 'Show password'); el.eye.setAttribute('aria-pressed', 'false');
    onInput(); doAnalyze();
    if (!matchMedia('(max-width: 860px)').matches) el.checker.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'center' });
  });
  generate();

  /* ---------- wire up ---------- */
  el.pw.addEventListener('input', onInput);
  el.pw.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); doAnalyze(); } });
  el.analyze.addEventListener('click', doAnalyze);
  el.reset.addEventListener('click', doReset);
  el.eye.addEventListener('click', toggleEye);
  // do not leave a typed password sitting in a restored/back-forward cached page
  addEventListener('pageshow', e => { if (e.persisted) { doReset(); generate(); } });

  renderLive(analyze(''));
  renderHistory();
  initHistory();

  /* ---------- loading screen ---------- */
  el.app.setAttribute('inert', '');
  let shown = false;
  function enter() {
    if (shown) return; shown = true;
    el.loader.classList.add('hide');
    el.app.removeAttribute('inert');
    document.body.classList.add('ready');
    el.checker.classList.add('rise');
    setTimeout(() => { el.loader.hidden = true; }, 700);
  }
  const minWait = reduced ? 300 : 2300;
  const t0 = performance.now();
  const go = () => setTimeout(enter, Math.max(0, minWait - (performance.now() - t0)));
  if (document.readyState === 'complete') go(); else addEventListener('load', go);
  setTimeout(enter, 5000); // safety net if a font or image stalls
  el.loader.addEventListener('click', enter);
  document.addEventListener('keydown', e => { if (!shown && (e.key === 'Escape' || e.key === 'Enter')) enter(); });
})();
