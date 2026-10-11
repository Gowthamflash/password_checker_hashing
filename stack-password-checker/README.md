# Stack Password Checking and Hashing

A cybersecurity toolkit with a Flask (Python) backend and an HTML / CSS / JavaScript frontend.
Every sensitive operation runs **in the browser**. The server never receives passwords, messages, keys or file contents.

| Page | What it does |
|---|---|
| `index.html` | **Password Checker** (live score, checks, suggestions, history) and **Password Generator** |
| `text-crypto.html` | **Text Encryption & Decryption** (AES-256-GCM, PBKDF2-SHA-256) |
| `hash.html` | **Hash Generator** (SHA-256, SHA-384, SHA-512 of text) |
| `file-hash.html` | **File Hashing** (drag and drop, many files, previews, streaming for large files, report download) |
| `file-crypto.html` | **File Encryption & Decryption** (`.stackenc` files, metadata preserved) |
| `verify.html` | **Hash Verification** (file vs pasted hash: MATCH / MISMATCH) |

## Run it
```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
python run.py
```
Open http://127.0.0.1:5000

Use `localhost`, `127.0.0.1` or HTTPS. Browsers only provide the Web Crypto API (needed for encryption) on secure origins.
You can also open `frontend/index.html` directly; history then stays in the browser, and the streaming worker falls back to the main thread.

## Project layout
```
run.py                       start the app (defines the top-level Flask instance `app`)
requirements.txt             Flask
pyproject.toml               Vercel entry point: entrypoint = "run:app"
backend/                     Python
  app.py                     pages, history API, security headers (strict CSP), rate limiting
  analyzer.py                password scoring (Python port) + command-line tool
  database.py                SQLite layer (history summaries only)
  config.py                  settings (environment variables)
frontend/                    served by Flask
  index.html, text-crypto.html, hash.html, file-hash.html, file-crypto.html, verify.html
  css/style.css              all styling; theme colors are the variables at the top
  js/config.js               frontend settings (history mode, file size limits)
  js/common.js               shared header/footer, icons, theme, toast, clipboard, downloads, drop zones, tabs
  js/script.js               password checker, generator, history
  js/stack-hash.js           SHA-256/384/512: Web Crypto helpers + incremental (streaming) implementation
  js/hash-worker.js          Web Worker that hashes large files chunk by chunk
  js/stack-crypto.js         AES-256-GCM / PBKDF2 for text and files (formats below)
  js/text-crypto.js, hash.js, file-hash.js, file-crypto.js, verify.js    one script per page
  assets/logo.png
tests/                       python -m unittest discover -s tests -t .
  tests/js/*.test.js         Node tests for hashing and encryption (run by tests/test_js.py)
data/                        SQLite database is created here
```

## Privacy and security design
- **Local only.** Password checking, generation, text/file encryption, text/file hashing and verification use the browser's Web Crypto API and never call the server. `tests/test_api.py` fails if those scripts contain `fetch`, `XMLHttpRequest`, storage, cookie or console calls.
- **No sensitive storage.** Passwords, messages, keys, plaintext and file contents are not written to localStorage, sessionStorage, cookies, SQLite, URLs or the console. The only saved data is the password-history summary `{level, score, passed, length}` and the theme preference.
- **Strict Content-Security-Policy** (set in `backend/app.py`): scripts only from this site, no inline scripts, no third-party scripts, no analytics, `connect-src 'self'`, `worker-src 'self'`, `object-src 'none'`. The only external resource is Google Fonts CSS/font files (styling only).
- **Careful file handling.** Selected files are only read as bytes. They are never executed or rendered as HTML. Image previews appear only for PNG, JPEG, GIF, WebP and SVG, shown through an `<img>` element (scripts in an SVG do not run). A decrypted file is saved as a download and never opened.
- **Safe DOM.** File names and results are inserted with `textContent`, never as HTML.
- History API: the server rejects any field it does not expect, so a password cannot be stored by accident. It is separated per browser by a random HttpOnly cookie, same-origin only, rate limited.
- `POST /api/analyze` and `STACK_ENABLE_ANALYZE_API=0` behave as before. The website does not use that endpoint.

## Cryptography details
**Text** (`stack-crypto.js`): output is Base64 of this JSON envelope
```json
{"v":1,"alg":"AES-256-GCM","kdf":"PBKDF2-SHA256","iter":600000,"salt":"<16 random bytes>","iv":"<12 random bytes>","ct":"<ciphertext + 16-byte tag>"}
```
**File** (`.stackenc`): `"STACKFE1"` | uint32 header length | header JSON `{v, alg, kdf, iter, salt, iv}` | AES-GCM( uint32 meta length | meta JSON `{name, type, size, lastModified}` | file bytes ).

- Key: PBKDF2-HMAC-SHA-256, 600,000 iterations, fresh 16-byte salt per encryption. Passwords are NFKC-normalized first so accented characters compare equal on every device.
- Cipher: AES-256-GCM, fresh 96-bit IV per encryption, 128-bit tag. The header (version, algorithms, iteration count, salt) is authenticated as GCM additional data. For files the name, type and size are inside the encrypted, authenticated part, so they are hidden and tamper-evident.
- Validation: the envelope or header is checked (format, version, algorithms, iteration range 100,000 to 2,000,000, salt/IV lengths, size limits) **before** any key derivation, so malformed or hostile input is rejected quickly. A wrong password and a tampered file give the same safe error.
- A lost password cannot be recovered. This is stated next to every encryption tool.

## Hashing details
- Text and files up to `STREAM_THRESHOLD_BYTES` (64 MB) use `crypto.subtle.digest` on the exact original bytes.
- Larger files (up to `FILE_HASH_MAX_BYTES`, 2 GB) are read in 4 MB chunks by a streaming SHA-2 implementation inside a Web Worker, so memory stays small. Both paths give identical results; `tests/js/hash.test.js` checks them against Node's crypto on many lengths and block boundaries.
- Hashing is one-way. There is no "decrypt hash" feature. The pages explain that a hash proves integrity only, does not hide the file, and does not prove a file is safe.
- Hash Verification trims whitespace, ignores letter case, accepts `sha256sum` style lines (`<hash>  <filename>`), checks the algorithm matches the hash length and offers to switch algorithm.

## Limits
- **File encryption is not for huge files.** AES-GCM here processes the whole file in memory (roughly 3 to 4 times its size), so `FILE_ENCRYPT_MAX_BYTES` defaults to 64 MB. Raise it in `frontend/js/config.js` only if your users have the RAM. Very large files need a chunked format, which this version does not implement.
- File hashing accepts up to 2 GB per file. Folders cannot be hashed.
- Encryption hides content, not the existence or approximate size of a message or file.
- The password score is a teaching heuristic, not a guarantee. The guess-time line is a rough estimate.

## API
| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/health` | | `{"status":"ok"}` |
| GET | `/api/history` | | `{"items":[{id,ts,level,score,passed,length}]}` |
| POST | `/api/history` | `{"level":"strong","score":94,"passed":5,"length":14}` | 201 `{"item":{...}}` |
| DELETE | `/api/history/<id>` | | 204 or 404 |
| DELETE | `/api/history` | | 204 |
| POST | `/api/analyze` | `{"password":"..."}` | analysis (password not echoed). Disable with `STACK_ENABLE_ANALYZE_API=0` |

## Settings
Backend (environment variables): `STACK_HOST`, `STACK_PORT`, `STACK_DEBUG`, `STACK_DB_PATH`, `STACK_MAX_HISTORY`, `STACK_ENABLE_ANALYZE_API`, `STACK_COOKIE_SECURE`, `STACK_RATE_LIMIT`, `STACK_ANALYZE_PER_MIN`, `STACK_WRITE_PER_MIN`. See `backend/config.py`.

Frontend (`frontend/js/config.js`): `HISTORY_MODE` (`'auto'`, `'server'`, `'local'`), `MAX_HISTORY`, `FILE_HASH_MAX_BYTES`, `FILE_HASH_MAX_FILES`, `STREAM_THRESHOLD_BYTES`, `FILE_ENCRYPT_MAX_BYTES`, `PREVIEW_MAX_BYTES`, `WORKER_URL`.

## Tests
```bash
python -m unittest discover -s tests -t .
```
Covers the API, scoring, Python/JavaScript scoring parity, page and CSP checks, and (needs Node.js 18+) the hashing and encryption libraries: known vectors, SHA-2 against Node crypto, round trips, unique salt/IV, wrong passwords, tampering, hostile envelopes and headers, empty files, and metadata preservation. Tests that need Node are skipped if Node is missing.

## Customizing
- **Password scoring**: edit `analyze()` in `frontend/js/script.js` (between `ANALYZER_START/END`) **and** `backend/analyzer.py`; the parity test fails if they disagree.
- **Look and feel**: `frontend/css/style.css` (light and dark themes are the two `:root` blocks).
- **Add a tool**: copy one of the tool pages, add a script, and add one line to the `PAGES` list in `frontend/js/common.js` (it builds the header, mobile menu and footer for every page).
- **Different frontend framework**: the backend API is plain JSON and only handles history summaries.

## Deploying on Vercel

Vercel runs the app as one Python function. `pyproject.toml` tells it where the Flask instance is (`entrypoint = "run:app"`); dependencies come from `requirements.txt`. Keep the folder layout above (`backend/`, `frontend/`, `run.py` at the repository root) and do not add a root `app.py` or a `vercel.json` unless you need one.

- **Vercel settings:** Framework Preset = Flask (auto-detected), Root Directory = repository root, Build/Install/Output commands = default (leave empty). Recommended environment variable: `STACK_ENABLE_ANALYZE_API=0` (the website does not use that endpoint).
- **History on Vercel:** SQLite cannot persist on Vercel (the deployed filesystem is read-only and `/tmp` is not shared between instances or kept between cold starts). When the `VERCEL` environment variable is present, server-side history is therefore off by default: `/api/history` answers `503` and the website keeps the history summary in the browser (localStorage), exactly like its existing fallback. Passwords are never stored in either place. For real server-side history you would need a separate hosted database and code changes; this project does not include one. `STACK_HISTORY_ENABLED=1` forces the SQLite history back on (only useful on a host with a persistent disk).
- **Other differences on Vercel:** the session cookie is `Secure` by default, and the in-memory rate limiter is per function instance (and sees Vercel's proxy address, not each visitor's), so it is only a basic guard there.
- Static pages, CSS, JS and images are served by Flask itself (so the strict Content-Security-Policy headers apply to them) and are not placed in `public/`.

## Deploying elsewhere
```bash
pip install gunicorn
STACK_COOKIE_SECURE=1 gunicorn -w 2 -b 0.0.0.0:8000 "backend.app:create_app()"
```
Serve over HTTPS (nginx or Caddy). Use a shared rate limiter if you run several workers, `ProxyFix` behind a proxy, and PostgreSQL for heavy traffic. Remove the Google Fonts allowance from the CSP if you self-host the fonts.
