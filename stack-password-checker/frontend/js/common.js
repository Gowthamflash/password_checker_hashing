/* Shared UI helpers for every page: icon sprite, header/footer, theme, toast, clipboard, downloads, drop zones.
 * Load this as the FIRST element inside <body>. Nothing here touches the network or logs values. */
(() => {
  'use strict';

  const P = {
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    unlock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M17.9 17.9A10.9 10.9 0 0 1 12 19c-6.4 0-10-7-10-7a18 18 0 0 1 5.1-5.9M9.9 5.2A10 10 0 0 1 12 5c6.4 0 10 7 10 7a18 18 0 0 1-2.2 3.2"/><path d="M1 1l22 22"/>',
    shield: '<path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/>',
    shieldchk: '<path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v5M14 11v5"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    reset: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
    scan: '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3M4 12h16"/>',
    alert: '<path d="M12 3l10 18H2L12 3zM12 10v5M12 18v.5"/>',
    bulb: '<path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z"/>',
    ruler: '<path d="M3 17l14-14 4 4L7 21l-4-4zM8 12l2 2M11 9l2 2M14 6l2 2"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5A6.5 6.5 0 0 1 21.5 20"/>',
    layers: '<path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>',
    repeat: '<path d="M17 2l4 4-4 4M3 11V9a3 3 0 0 1 3-3h15M7 22l-4-4 4-4M21 13v2a3 3 0 0 1-3 3H3"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
    chev: '<path d="M9 6l6 6-6 6"/>',
    db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
    upload: '<path d="M12 15V3M7 8l5-5 5 5M4 21h16"/>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5zM14 3v5h5"/>',
    filelock: '<path d="M13 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h4M13 3l5 5v2M13 3v5h5"/><rect x="13" y="14" width="8" height="7" rx="1.5"/><path d="M15 14v-1.5a2 2 0 0 1 4 0V14"/>',
    hash: '<path d="M5 9h14M5 15h14M10 3L8 21M16 3l-2 18"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.5"/>',
    image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.6"/><path d="M21 16l-5-5-8 9"/>',
    dice: '<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1"/><circle cx="15" cy="9" r="1"/><circle cx="9" cy="15" r="1"/><circle cx="15" cy="15" r="1"/>',
    arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    type: '<path d="M4 7V4h16v3M9 20h6M12 4v16"/>',
    okc: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',
    xc: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    compare: '<path d="M8 3L4 7l4 4M4 7h12M16 21l4-4-4-4M20 17H8"/>'
  };
  const icon = (n, s = 18) => `<svg class="i" width="${s}" height="${s}" aria-hidden="true"><use href="#i-${n}"/></svg>`;

  // ---- icon sprite (inserted right away so inline <use> references resolve) ----
  document.body.insertAdjacentHTML('afterbegin',
    '<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false">' +
    Object.keys(P).map(n => `<symbol id="i-${n}" viewBox="0 0 24 24">${P[n]}</symbol>`).join('') + '</svg>');

  // ---- storage (non-sensitive UI preference only: the theme) ----
  const store = (() => {
    try { const k = '__t'; localStorage.setItem(k, '1'); localStorage.removeItem(k); return localStorage; }
    catch (e) { const m = {}; return { getItem: k => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); } }; }
  })();
  const KEY_T = 'stack-pc:theme';

  // ---- theme ----
  const root = document.documentElement;
  function applyTheme(t) {
    root.dataset.theme = t;
    const meta = document.getElementById('metaTheme');
    if (meta) meta.setAttribute('content', t === 'dark' ? '#05090A' : '#F2F7F4');
    const b = document.getElementById('themeBtn');
    if (b) {
      b.innerHTML = icon(t === 'dark' ? 'sun' : 'moon', 18);
      b.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    }
  }
  applyTheme(store.getItem(KEY_T) === 'light' ? 'light' : 'dark');

  // ---- header / footer ----
  const PAGES = [
    ['checker', 'index.html', 'Checker'],
    ['text-crypto', 'text-crypto.html', 'Text Crypto'],
    ['hash', 'hash.html', 'Hash'],
    ['file-hash', 'file-hash.html', 'File Hash'],
    ['file-crypto', 'file-crypto.html', 'File Crypto'],
    ['verify', 'verify.html', 'Verify'],
    ['about', 'index.html#about', 'About']
  ];
  const current = document.body.dataset.page || '';
  const linkHtml = ([id, href, label]) => `<a href="${href}"${id === current ? ' aria-current="page"' : ''}>${label}</a>`;

  function renderChrome() {
    const h = document.getElementById('siteHeader');
    if (h) {
      h.outerHTML = `<header class="nav"><div class="wrap nav-in">
        <a class="brand" href="index.html" aria-label="Stack Password Checking and Hashing — home">
          <span class="lt s glow"><img src="assets/logo.png" alt="Stack logo"></span>
          <span class="bt"><b class="ff-d">STACK</b><small>Password Checking &amp; Hashing</small></span></a>
        <nav class="links" aria-label="Primary">${PAGES.map(linkHtml).join('')}</nav>
        <button class="ibtn theme" id="themeBtn" type="button" aria-label="Switch theme"></button>
        <button class="ibtn burger" id="burger" type="button" aria-label="Open menu" aria-expanded="false" aria-controls="mpanel">${icon('menu', 20)}</button>
      </div>
      <nav class="mpanel" id="mpanel" aria-label="Mobile" hidden>${PAGES.map(([id, href, label]) =>
        `<a href="${href}"${id === current ? ' aria-current="page"' : ''}>${label}${icon('chev', 16)}</a>`).join('')}</nav></header>`;
    }
    const f = document.getElementById('siteFooter');
    if (f) {
      f.outerHTML = `<footer class="foot"><div class="wrap foot-in">
        <span class="lt m"><img src="assets/logo.png" alt="Stack logo"></span>
        <div><b>STACK PASSWORD CHECKING AND HASHING</b><div class="d">Cybersecurity Password &amp; Hashing Toolkit</div></div>
        <div class="r">Built for cybersecurity learning and awareness.<br>© 2026 Stack Password Checking and Hashing</div></div></footer>`;
    }
    applyTheme(root.dataset.theme);
    const themeBtn = document.getElementById('themeBtn'), burger = document.getElementById('burger'), mpanel = document.getElementById('mpanel');
    if (!themeBtn) return;
    themeBtn.addEventListener('click', () => {
      const t = root.dataset.theme === 'dark' ? 'light' : 'dark';
      applyTheme(t); try { store.setItem(KEY_T, t); } catch (e) { /* ignore */ }
    });
    const setMenu = open => {
      mpanel.hidden = !open;
      burger.setAttribute('aria-expanded', String(open));
      burger.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
      burger.innerHTML = icon(open ? 'x' : 'menu', 20);
    };
    burger.addEventListener('click', () => setMenu(mpanel.hidden));
    mpanel.addEventListener('click', e => { if (e.target.closest('a')) setMenu(false); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !mpanel.hidden) { setMenu(false); burger.focus(); } });
    const nav = document.querySelector('.nav');
    document.addEventListener('click', e => { if (!mpanel.hidden && !e.composedPath().includes(nav)) setMenu(false); });
    addEventListener('resize', () => { if (innerWidth > 1180) setMenu(false); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', renderChrome); else renderChrome();

  // ---- toast ----
  let toastT;
  function toast(msg) {
    let t = document.getElementById('toast');
    if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; t.setAttribute('role', 'status'); t.setAttribute('aria-live', 'polite'); document.body.appendChild(t); }
    t.textContent = msg; t.classList.add('show');
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2800);
  }

  // ---- clipboard / downloads ----
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
      document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
      ta.remove(); return ok;
    }
  }
  function safeFilename(name, fallback = 'file') {
    let n = String(name || '').replace(/[\u0000-\u001f\u007f<>:"/\\|?*]+/g, '_').replace(/^[.\s]+|[.\s]+$/g, '');
    if (/^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(n)) n = '_' + n;
    return n.slice(0, 120) || fallback;
  }
  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = safeFilename(filename); a.rel = 'noopener'; a.style.display = 'none';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 15000);
  }
  const downloadText = (text, filename) => downloadBlob(new Blob([text], { type: 'text/plain;charset=utf-8' }), filename);

  function formatBytes(n) {
    if (!Number.isFinite(n)) return '—';
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + ' ' + u[i];
  }
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---- drag & drop zone ----
  function dropzone(zone, input, onFiles) {
    const pick = () => { const f = [...input.files]; input.value = ''; if (f.length) onFiles(f); };
    input.addEventListener('change', pick);
    zone.addEventListener('click', e => { if (e.target !== input) input.click(); });
    ['dragenter', 'dragover'].forEach(t => zone.addEventListener(t, e => { e.preventDefault(); zone.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(t => zone.addEventListener(t, e => { e.preventDefault(); zone.classList.remove('over'); }));
    zone.addEventListener('drop', e => { const f = [...(e.dataTransfer ? e.dataTransfer.files : [])]; if (f.length) onFiles(f); });
  }
  // Dropping a file anywhere else on the page must not navigate away to it.
  ['dragover', 'drop'].forEach(t => window.addEventListener(t, e => { if (!e.target.closest || !e.target.closest('.drop')) e.preventDefault(); }));


  // ---- status line (aria-live) ----
  function status(el, kind, msg) {
    el.className = 'status' + (kind ? ' ' + kind : '');
    el.textContent = '';
    if (!msg) return el;
    const lead = kind === 'work' ? '<span class="busy" aria-hidden="true"></span>' : kind === 'ok' ? icon('okc', 18) : kind === 'bad' ? icon('xc', 18) : '';
    el.innerHTML = lead + '<span>' + esc(msg) + '</span>';
    return el;
  }

  // ---- accessible tabs (arrow keys, Home/End) ----
  function tabs(list, onChange) {
    const btns = [...list.querySelectorAll('[role=tab]')];
    const select = (btn, focus) => {
      btns.forEach(b => {
        const on = b === btn;
        b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1;
        document.getElementById(b.getAttribute('aria-controls')).hidden = !on;
      });
      if (focus) btn.focus();
      if (onChange) onChange(btn.id);
    };
    btns.forEach((b, i) => {
      b.addEventListener('click', () => select(b, false));
      b.addEventListener('keydown', e => {
        const k = e.key; let j = null;
        if (k === 'ArrowRight') j = (i + 1) % btns.length; else if (k === 'ArrowLeft') j = (i - 1 + btns.length) % btns.length;
        else if (k === 'Home') j = 0; else if (k === 'End') j = btns.length - 1;
        if (j !== null) { e.preventDefault(); select(btns[j], true); }
      });
    });
    return select;
  }

  const PREVIEW_EXT = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'];
  const PREVIEW_MIME = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml'];
  function isPreviewImage(file) {
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    return PREVIEW_EXT.includes(ext) && PREVIEW_MIME.includes(file.type);
  }

  const stamp = () => new Date().toISOString();
  function toggleEye(btn, input) {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.innerHTML = icon(show ? 'eyeoff' : 'eye', 20);
    btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    btn.setAttribute('aria-pressed', String(show));
  }

  window.Stack = { icon, status, tabs, isPreviewImage, toast, copyText, downloadBlob, downloadText, safeFilename, formatBytes, esc, dropzone, stamp, toggleEye,
    cfg: () => window.STACK_CONFIG || {}, store };
})();
