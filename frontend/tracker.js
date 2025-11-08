// Lightweight tracker: sends page visit with optional username
(function(){
  try {
    var API_BASE = (typeof window !== 'undefined' && window.FEELINGS_API_BASE) ? window.FEELINGS_API_BASE : '';
    var cookies = document.cookie || '';
    var m = cookies.match(/(?:^|; )username=([^;]+)/);
    var username = m ? decodeURIComponent(m[1]) : (localStorage.getItem('username') || null);
    var payload = {
      username: username || null,
      page: location.pathname,
      title: document.title || null,
      referrer: document.referrer || null,
      ua: navigator.userAgent || null
    };
    // send without blocking navigation
    fetch(apiUrl('/api/visit'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
      credentials: 'omit'
    }).catch(function(){});
  } catch(e) {}
})();
