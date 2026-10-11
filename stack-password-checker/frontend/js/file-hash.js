/* File Hashing page. Files are read and hashed in the browser (Web Crypto, or a streaming worker for large files).
 * File contents are never uploaded, stored or executed. */
(() => {
  'use strict';
  const S = window.Stack, H = window.StackHash, cfg = S.cfg();
  const $ = s => document.querySelector(s);
  const el = { drop: $('#drop'), browse: $('#browse'), input: $('#fileIn'), algo: $('#fAlgo'), go: $('#fGo'), cancel: $('#fCancel'),
    msg: $('#fMsg'), list: $('#fList'), sum: $('#fSum'), count: $('#fCount'), report: $('#fReport'), clearAll: $('#fClearAll'), max: $('#maxInfo') };
  const METHOD = { webcrypto: 'Web Crypto API', 'worker-stream': 'streaming in a worker', stream: 'streaming' };
  let items = [], seq = 0, running = false, ctl = null;
  el.max.textContent = S.formatBytes(cfg.FILE_HASH_MAX_BYTES);

  S.dropzone(el.drop, el.input, addFiles);

  function addFiles(files) {
    const problems = [];
    let added = 0;
    for (const f of files) {
      if (items.length >= cfg.FILE_HASH_MAX_FILES) { problems.push(`Only ${cfg.FILE_HASH_MAX_FILES} files can be hashed at once.`); break; }
      if (f.size > cfg.FILE_HASH_MAX_BYTES) { problems.push(`“${f.name}” is larger than ${S.formatBytes(cfg.FILE_HASH_MAX_BYTES)}.`); continue; }
      if (items.some(i => i.file.name === f.name && i.file.size === f.size && i.file.lastModified === f.lastModified)) { problems.push(`“${f.name}” is already in the list.`); continue; }
      const it = { id: ++seq, file: f, results: {}, state: 'ready', progress: 0, error: '', method: '', previewUrl: null };
      items.push(it); el.list.appendChild(buildItem(it)); updateItem(it); added++;
    }
    if (problems.length) S.status(el.msg, 'bad', problems.slice(0, 3).join(' ') + (problems.length > 3 ? ` (+${problems.length - 3} more)` : ''));
    else if (added) S.status(el.msg, '', '');
    refresh();
  }

  function buildItem(it) {
    const li = document.createElement('li'); li.className = 'fi'; li.dataset.id = it.id;
    const th = document.createElement('div'); th.className = 'th';
    if (S.isPreviewImage(it.file) && it.file.size <= cfg.PREVIEW_MAX_BYTES) {
      it.previewUrl = URL.createObjectURL(it.file);
      const img = document.createElement('img'); img.src = it.previewUrl; img.alt = 'Preview of ' + it.file.name; img.loading = 'lazy';
      img.addEventListener('error', () => { img.remove(); th.innerHTML = S.icon('image', 24); });
      th.appendChild(img);
    } else th.innerHTML = S.icon('file', 24);
    const main = document.createElement('div'); main.style.minWidth = '0';
    const nm = document.createElement('div'); nm.className = 'nm'; nm.textContent = it.file.name;
    const sub = document.createElement('div'); sub.className = 'sub';
    main.append(nm, sub);
    const act = document.createElement('div'); act.className = 'act';
    const cp = document.createElement('button'); cp.type = 'button'; cp.className = 'ibtn cp'; cp.innerHTML = S.icon('copy', 17);
    cp.addEventListener('click', async () => {
      const hex = it.results[el.algo.value];
      if (hex) S.toast((await S.copyText(hex)) ? 'Hash copied.' : 'Could not copy. Select the hash and copy it manually.');
    });
    const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'ibtn'; rm.innerHTML = S.icon('x', 17);
    rm.setAttribute('aria-label', 'Remove ' + it.file.name);
    rm.addEventListener('click', () => removeItem(it, li));
    act.append(cp, rm);
    const res = document.createElement('div'); res.className = 'res';
    li.append(th, main, act, res);
    it.dom = { li, sub, res, cp };
    return li;
  }

  function updateItem(it) {
    const d = it.dom, algo = el.algo.value, f = it.file;
    const big = f.size > cfg.STREAM_THRESHOLD_BYTES ? ' · large file, streamed' : '';
    d.sub.textContent = `${S.formatBytes(f.size)}${f.size ? '' : ' (empty file)'} · ${f.type || 'unknown type'}${big}`;
    d.cp.setAttribute('aria-label', `Copy ${algo} hash of ${f.name}`);
    d.cp.disabled = !it.results[algo]; d.cp.style.display = Object.keys(it.results).length ? '' : 'none';
    d.res.textContent = '';
    if (it.state === 'hashing') {
      const pct = Math.round(it.progress * 100);
      const t = document.createElement('div'); t.className = 'state'; t.textContent = `Hashing ${algo}… ${pct}%`;
      const bar = document.createElement('div'); bar.className = 'prog'; bar.setAttribute('role', 'progressbar');
      bar.setAttribute('aria-label', 'Hashing ' + f.name); bar.setAttribute('aria-valuemin', '0'); bar.setAttribute('aria-valuemax', '100'); bar.setAttribute('aria-valuenow', pct);
      const i = document.createElement('i'); i.style.width = pct + '%'; bar.appendChild(i);
      d.res.append(t, bar); return;
    }
    if (it.state === 'error') { const t = document.createElement('div'); t.className = 'state bad'; t.textContent = it.error; d.res.appendChild(t); return; }
    const algos = Object.keys(H.ALGOS).filter(a => it.results[a]);
    if (algos.length) {
      algos.forEach(a => {
        const row = document.createElement('div'); row.className = 'rh';
        const al = document.createElement('span'); al.className = 'al'; al.textContent = a;
        const p = document.createElement('p'); p.className = 'hashline'; p.textContent = it.results[a];
        row.append(al, p); d.res.appendChild(row);
      });
      if (!it.results[algo]) { const t = document.createElement('div'); t.className = 'state'; t.textContent = `Not hashed with ${algo} yet.`; d.res.appendChild(t); }
      else if (it.method) { const t = document.createElement('div'); t.className = 'state'; t.textContent = `Computed with ${METHOD[it.method] || it.method}.`; d.res.appendChild(t); }
    } else {
      const t = document.createElement('div'); t.className = 'state';
      t.textContent = it.state === 'cancelled' ? 'Cancelled. Press Generate hash to try again.' : 'Not hashed yet.';
      d.res.appendChild(t);
    }
  }

  function refresh() {
    const n = items.length, done = items.filter(i => Object.keys(i.results).length).length;
    el.sum.hidden = n === 0;
    el.count.textContent = `${n} file${n === 1 ? '' : 's'} selected${done ? `, ${done} hashed` : ''}`;
    el.go.disabled = running || n === 0;
    el.cancel.hidden = !running;
    el.report.disabled = done === 0;
  }

  function removeItem(it, li) {
    if (running && it.state === 'hashing' && ctl) ctl.abort();
    if (it.previewUrl) URL.revokeObjectURL(it.previewUrl);
    items = items.filter(x => x !== it);
    li.classList.add('removing');
    setTimeout(() => li.remove(), 280);
    refresh();
  }
  el.clearAll.addEventListener('click', () => {
    if (ctl) ctl.abort();
    items.forEach(i => i.previewUrl && URL.revokeObjectURL(i.previewUrl));
    items = []; el.list.textContent = ''; S.status(el.msg, '', ''); refresh();
  });

  async function hashAll() {
    const algo = el.algo.value, todo = items.filter(i => !i.results[algo] && i.state !== 'error');
    if (!todo.length) { S.status(el.msg, 'ok', `Everything is already hashed with ${algo}.`); return; }
    running = true; ctl = new AbortController(); refresh();
    S.status(el.msg, 'work', `Hashing ${todo.length} file${todo.length === 1 ? '' : 's'} with ${algo}…`);
    let okCount = 0, failed = 0, cancelled = false;
    for (const it of todo) {
      if (!items.includes(it)) continue;
      it.state = 'hashing'; it.progress = 0; updateItem(it);
      let lastPaint = 0;
      try {
        const r = await H.hashBlob(it.file, algo, {
          signal: ctl.signal, thresholdBytes: cfg.STREAM_THRESHOLD_BYTES, workerUrl: cfg.WORKER_URL,
          onProgress: v => { it.progress = v; const n = Date.now(); if (n - lastPaint > 60 || v >= 1) { lastPaint = n; updateItem(it); } }
        });
        it.results[algo] = r.hex; it.method = r.method; it.state = 'done'; okCount++;
      } catch (e) {
        if (e && e.name === 'AbortError') { it.state = 'cancelled'; cancelled = true; updateItem(it); break; }
        it.state = 'error'; failed++;
        it.error = (e && e.readError) || (e && e.name === 'NotReadableError') || (e && e.name === 'NotFoundError')
          ? 'This file could not be read. It may be a folder, or it may have been moved or changed.' : 'Could not hash this file in this browser.';
      }
      updateItem(it);
    }
    running = false; ctl = null; refresh(); items.forEach(updateItem);
    if (cancelled) S.status(el.msg, '', 'Cancelled.');
    else if (failed) S.status(el.msg, 'bad', `${okCount} hashed, ${failed} could not be read.`);
    else S.status(el.msg, 'ok', `Done. ${okCount} file${okCount === 1 ? '' : 's'} hashed with ${algo}.`);
  }
  el.go.addEventListener('click', hashAll);
  el.cancel.addEventListener('click', () => { if (ctl) ctl.abort(); });
  el.browse.addEventListener('click', e => e.stopPropagation() || el.input.click());
  el.algo.addEventListener('change', () => { items.forEach(updateItem); });

  el.report.addEventListener('click', () => {
    const line = s => String(s).replace(/[\r\n]+/g, ' ');
    const out = ['Stack Password Checking and Hashing: File Hash Report', `Generated: ${S.stamp()}`,
      'Hashed locally in the browser. Files were not uploaded.', ''];
    Object.keys(H.ALGOS).forEach(a => {
      const rows = items.filter(i => i.results[a]);
      if (!rows.length) return;
      out.push(`[${a}]`);
      rows.forEach(i => out.push(`${i.results[a]}  ${line(i.file.name)}  (${i.file.size} bytes, ${line(i.file.type || 'unknown type')})`));
      out.push('');
    });
    out.push('A hash verifies integrity only. It does not encrypt the file and does not prove the file is safe.', '');
    S.downloadText(out.join('\n'), 'file-hash-report.txt'); S.toast('Report download started.');
  });

  addEventListener('pagehide', () => items.forEach(i => i.previewUrl && URL.revokeObjectURL(i.previewUrl)));
  refresh();
})();
