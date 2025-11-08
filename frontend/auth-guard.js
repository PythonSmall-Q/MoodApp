(function(){
  // Simple auth guard used by frontend pages.
  // Determines username by cookie 'username' or localStorage 'username'.
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return decodeURIComponent(parts.pop().split(';').shift() || '');
    return '';
  }
  function getUsername() {
    const c = getCookie('username');
    if (c) return c;
    try { return localStorage.getItem('username') || ''; } catch { return ''; }
  }
  const path = location.pathname || '';
  const file = path.split('/').pop() || '';
  // Skip guard for admin page(s)
  if (file === 'admin.html' || path.includes('/admin')) return;
  // If currently on login page and already logged in -> go to ai-chat (we'll verify via server)
  if (file === 'login.html' || file === 'login') {
    // check server session with a small retry/backoff to tolerate timing/network flakes
    (async function checkAndRedirect() {
      // if we just logged in (another page set this flag), give the server more time
      let maxAttempts = 4;
      try {
        const just = sessionStorage.getItem('just_logged_in');
        if (just && (Date.now() - Number(just) < 20000)) { maxAttempts = 10; }
      } catch(e) {}
      let found = null;
      for (let i = 0; i < maxAttempts; i++) {
        try {
          const r = await fetch(typeof apiUrl === 'function' ? apiUrl('/api/whoami') : '/api/whoami', { method: 'GET', credentials: 'include' });
          const j = await r.json().catch(()=>null);
          const u = (j && j.data && j.data.username) ? j.data.username : null;
          if (u) { found = u; break; }
        } catch (e) {
          // ignore transient error
        }
        // small backoff
        await new Promise(r => setTimeout(r, 300 * (i+1)));
      }
      if (found) {
        // avoid immediate redirect storms
        try { sessionStorage.removeItem('just_logged_in'); } catch(e) {}
        setTimeout(() => { location.href = './ai-chat.html'; }, 80);
        return;
      }
      // fallback to client-side check
      const username = getUsername(); if (username) { setTimeout(()=>{ location.href = './ai-chat.html'; }, 100); }
    })();
    return;
  }
  // For all other pages, verify session via server. If not authenticated, redirect to login.
  // For all other pages, verify session via server with retry and a small grace delay before redirect.
  (async function verifyAndMaybeRedirect(){
    const maxAttempts = 3;
    let ok = null;
    for (let i = 0; i < maxAttempts; i++) {
        try {
          const r = await fetch(typeof apiUrl === 'function' ? apiUrl('/api/whoami') : '/api/whoami', { method: 'GET', credentials: 'include' });
          const j = await r.json().catch(()=>null);
          const u = (j && j.data && j.data.username) ? j.data.username : null;
          if (u) { ok = u; break; }
        } catch (e) {}
      await new Promise(r => setTimeout(r, 200));
    }
    if (!ok) {
      // fallback to client-side cookie/localStorage check
      const username = getUsername();
      if (!username) {
        try { sessionStorage.setItem('post_login_redirect', location.pathname + location.search); } catch {}
        // small defer to reduce redirect storms
        setTimeout(() => { location.href = './login.html'; }, 120);
      }
    }
  })();
})();
