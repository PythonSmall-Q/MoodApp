// Reusable maintenance popup for frontend pages
// Fetches /api/maintenance and shows a dismissable top-right popup when
// there are maintenance items active or starting within the next 24 hours.
(function () {
  function escapeHtml(s) { return String(s||'').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }

  async function fetchMaintenance() {
    try {
      const r = await fetch(apiUrl('/api/maintenance'));
      if (!r.ok) return [];
      const j = await r.json().catch(() => ({}));
      return j.maintenance || [];
    } catch (e) { return []; }
  }

  function isRelevant(item, now, soon) {
    if (!item) return false;
    // treat active undefined as active
    if (typeof item.active !== 'undefined' && Number(item.active) === 0) return false;
    const start = item.start_time ? new Date(item.start_time) : null;
    const end = item.end_time ? new Date(item.end_time) : null;
    // If no start/end and marked active, consider relevant
    if (!start && !end) return true;
    // If it is currently active
    if (start && end && start <= now && end >= now) return true;
    // If it starts within next 24 hours and hasn't ended yet
    if (start && start <= soon && (end == null || end >= now)) return true;
    // If it ends within next 24 hours and has already started (or no start)
    if (end && end >= now && end <= soon && (!start || start <= soon)) return true;
    return false;
  }

  function createPopup(items) {
    if (!items || !items.length) return;
    if (sessionStorage.getItem('maint_popup_dismissed')) return;
    if (document.getElementById('maint-popup')) return;

    const popup = document.createElement('div');
    popup.id = 'maint-popup';
    popup.style.position = 'fixed';
    popup.style.top = '18px';
    popup.style.right = '18px';
    popup.style.width = '320px';
    popup.style.maxWidth = 'calc(100% - 36px)';
    popup.style.background = '#fff';
    popup.style.boxShadow = '0 6px 24px rgba(0,0,0,0.14)';
    popup.style.borderRadius = '8px';
    popup.style.padding = '12px';
    popup.style.zIndex = '99999';
    popup.style.fontFamily = 'Segoe UI, Roboto, system-ui, -apple-system, "Helvetica Neue", Arial';

    const close = document.createElement('button');
    close.textContent = '×';
    close.setAttribute('aria-label','dismiss');
    close.style.position = 'absolute';
    close.style.top = '6px';
    close.style.right = '8px';
    close.style.border = 'none';
    close.style.background = 'transparent';
    close.style.fontSize = '18px';
    close.style.cursor = 'pointer';

    close.addEventListener('click', () => {
      popup.style.display = 'none';
      try { sessionStorage.setItem('maint_popup_dismissed','1'); } catch (e) {}
    });

    const title = document.createElement('div');
    title.style.fontSize = '15px';
    title.style.fontWeight = '600';
    title.style.marginBottom = '6px';
    title.textContent = '系统维护提醒';

    const body = document.createElement('div');
    body.style.fontSize = '13px';
    body.style.color = '#222';
    body.style.maxHeight = '260px';
    body.style.overflow = 'auto';

    const html = items.slice(0,3).map(m => {
      const t = escapeHtml(m.title || '(无标题)');
      const d = escapeHtml((m.details || '').slice(0,260));
      return `<div style="margin-bottom:10px"><div style=\"font-weight:600;margin-bottom:4px\">${t}</div><div style=\"color:#333\">${d}</div></div>`;
    }).join('<hr style="border:none;border-top:1px solid #eee;margin:8px 0">');

    body.innerHTML = html;
    popup.appendChild(close);
    popup.appendChild(title);
    popup.appendChild(body);
    document.body.appendChild(popup);
  }

  async function init() {
    try {
      const now = new Date();
      const soon = new Date(now.getTime() + 24*60*60*1000);
      const list = await fetchMaintenance();
      const relevant = (list||[]).filter(i => isRelevant(i, now, soon));
      if (relevant.length) createPopup(relevant);
    } catch (e) { /* silent */ }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    setTimeout(init, 0);
  }

})();
