// csrf helper: automatically add X-CSRF-Token header from localStorage for same-origin POST/PUT/PATCH/DELETE requests
// Also add a lightweight global unhandledrejection handler to reduce noisy console errors coming
(function(){
  // Global diagnostics: suppress a common Chrome/extension noisy message that appears after long idle
  // "A listener indicated an asynchronous response by returning true, but the message channel closed before a response was received"
  // We don't swallow all rejections — we prevent default for this known symptom and log others for diagnostics.
  try {
    window.addEventListener && window.addEventListener('unhandledrejection', function (e) {
      try {
        const reason = e && e.reason;
        const msg = (typeof reason === 'string') ? reason : (reason && reason.message) || String(reason || '');
        if (msg && msg.includes('A listener indicated an asynchronous response by returning true')) {
          // Prefer a console.warn so developer can still see suppressed occurrences if they inspect warnings
          console.warn('Suppressed extension async-response message:', msg);
          if (e && typeof e.preventDefault === 'function') e.preventDefault();
          return;
        }
        // For other unhandled rejections keep the default behavior but also log details to help diagnosis
        console.error('Unhandled promise rejection captured (csrf.js):', reason);
      } catch (inner) { try { console.error('Error in global unhandledrejection handler', inner); } catch(_){} }
    });
  } catch (e) {}
  const API_BASE = (typeof window !== 'undefined' && window.API_BASE) ? window.API_BASE : window.location.origin;
  // Prefer reading csrf token from cookie; fallback to GET /api/csrf
  function readCsrfFromCookie() {
    try {
      const m = document.cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('csrf_token='));
      if (!m) return null;
      return decodeURIComponent(m.split('=')[1] || '') || null;
    } catch (e) { return null; }
  }
  (async function ensureCsrf(){
    try {
      const existing = readCsrfFromCookie();
      if (existing) return;
      // Try a few times in case of transient network/session timing issues
      let token = null;
      for (let i = 0; i < 3; i++) {
        try {
          const res = await fetch(typeof apiUrl === 'function' ? apiUrl('/api/csrf') : new URL('/api/csrf', API_BASE).toString(), { method: 'GET', credentials: 'include' });
          const j = await res.json().catch(()=>null);
          token = j && j.data && j.data.csrf_token ? j.data.csrf_token : (j && j.csrf_token) || null;
          if (token) break;
        } catch (e) {}
        await new Promise(r => setTimeout(r, 200 * (i+1)));
      }
      if (token) {
        // set cookie so future loads have it; path=/ Max-Age=1 day
        try { document.cookie = `csrf_token=${encodeURIComponent(token)}; Path=/; Max-Age=${24*3600}; SameSite=Lax`; } catch (e) {}
      }
    } catch (e) { /* ignore */ }
  })();

  const origFetch = window.fetch;
  window.fetch = function(input, init){
    try {
      const urlStr = (typeof input === 'string') ? input : (input && input.url) || '';
      const reqUrl = new URL(urlStr, window.location.href);
      const method = (init && init.method) || 'GET';
      let shouldAttach = ['POST','PUT','PATCH','DELETE'].includes(String(method).toUpperCase());
      if (shouldAttach) {
        try {
          const apiOrigins = [window.location.origin];
          if (typeof window.FEELINGS_API_BASE === 'string' && window.FEELINGS_API_BASE) apiOrigins.push((new URL(window.FEELINGS_API_BASE)).origin);
          try { apiOrigins.push((new URL(API_BASE)).origin); } catch(e){}
          shouldAttach = apiOrigins.includes(reqUrl.origin);
        } catch(e) { shouldAttach = false; }
      }
      if (shouldAttach) {
        const token = readCsrfFromCookie();
        init = init || {};
        // ensure credentials are sent so server can read HttpOnly session cookie
        try { init.credentials = init.credentials || 'include'; } catch (e) {}
        // normalize headers to a plain object or Headers instance for easy manipulation
        if (!init.headers) init.headers = {};
        if (init.headers instanceof Headers) {
          if (token) init.headers.set('X-CSRF-Token', token);
        } else if (Array.isArray(init.headers)) {
          if (token) init.headers.push(['X-CSRF-Token', token]);
        } else {
          // plain object
          if (token) init.headers = Object.assign({}, init.headers || {}, { 'X-CSRF-Token': token });
        }
      }
    } catch (e) {}
    return origFetch.apply(this, arguments);
  };
})();