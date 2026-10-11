/* Frontend settings. Edit freely. Any value can also be overridden by defining window.STACK_CONFIG before this file loads.
 *
 * HISTORY_MODE (password checker history summaries only)
 *   'auto'   - use the Python backend when it is reachable, otherwise this browser's localStorage (default)
 *   'server' - always use the backend (shows a message if it cannot be reached)
 *   'local'  - never talk to the backend; history stays in this browser
 *
 * Passwords, messages, encryption keys and file contents are always handled in the browser
 * and are never sent to the backend.
 *
 * File limits are in bytes.
 */
window.STACK_CONFIG = Object.assign({
  API_BASE: '/api',
  HISTORY_MODE: 'auto',
  MAX_HISTORY: 30,

  FILE_HASH_MAX_BYTES: 2 * 1024 * 1024 * 1024,      // largest file the hashing tools accept (2 GiB)
  FILE_HASH_MAX_FILES: 50,                          // files per batch in the File Hash tool
  STREAM_THRESHOLD_BYTES: 64 * 1024 * 1024,         // above this, hash in a streaming worker instead of one Web Crypto call
  FILE_ENCRYPT_MAX_BYTES: 64 * 1024 * 1024,         // largest file the encryption tool accepts (64 MiB)
  PREVIEW_MAX_BYTES: 25 * 1024 * 1024,              // largest image shown as a preview
  WORKER_URL: 'js/hash-worker.js'
}, window.STACK_CONFIG || {});
