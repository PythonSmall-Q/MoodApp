// small-popup.js
// Lightweight reusable top-center popup used for short notices (same form as login error popup)
(function(){
    if (window._smallPopupInit) return;
    window._smallPopupInit = true;

    const style = document.createElement('style');
    style.textContent = `
    .small-popup {
        display: none;
        position: fixed;
        top: 32px;
        left: 50%;
        transform: translateX(-50%);
        padding: 16px 40px 16px 24px;
        border-radius: 16px;
        box-shadow: 0 4px 24px rgba(58,122,254,0.18);
        font-size: 1.1rem;
        z-index: 1001;
        align-items: center;
        min-width: 260px;
        max-width: 90vw;
        animation: fadeInPopup 0.4s;
    }
    .small-popup .popup-icon { font-size: 1.5rem; margin-right: 12px; vertical-align: middle; }
    .small-popup .popup-text { vertical-align: middle; }
    .small-popup .popup-close {
        position: absolute; right: 16px; top: 10px; font-size: 1.3rem; cursor: pointer; font-weight: bold; transition: color 0.2s;
    }
    .small-popup.error { background: linear-gradient(90deg, #fff 80%, #ffeaea 100%); color: #d32f2f; }
    .small-popup.error .popup-close { color: #d32f2f; }
    .small-popup.success { background: linear-gradient(90deg, #fff 80%, #eaffea 100%); color: #2e7d32; }
    .small-popup.success .popup-close { color: #2e7d32; }
    @keyframes fadeInPopup { from { opacity: 0; transform: translateX(-50%) scale(0.95); } to { opacity: 1; transform: translateX(-50%) scale(1); } }
    `;
    if (document.head) {
        document.head.appendChild(style);
    } else {
        document.addEventListener('DOMContentLoaded', function(){ try { document.head && document.head.appendChild(style); } catch(e){} });
    }

    // container ensures z-index stacking independent of other elements
    var container = null;
    function ensureContainer() {
        if (container) return container;
        var existing = document.getElementById('small-popup-container');
        if (existing) { container = existing; return container; }
        container = document.createElement('div');
        container.id = 'small-popup-container';
        if (document.body) {
            try { document.body.appendChild(container); } catch(e) { /* ignore */ }
        } else {
            document.addEventListener('DOMContentLoaded', function(){ try { if (!document.getElementById('small-popup-container')) document.body.appendChild(container); } catch(e){} });
        }
        return container;
    }

    function showSmallPopup(text, opts) {
        opts = opts || {};
        const type = opts.type === 'success' ? 'success' : 'error';
        const duration = typeof opts.duration === 'number' ? opts.duration : 2500;

        // ensure container exists (may wait for DOMContentLoaded)
        ensureContainer();
        let popup = document.getElementById('small-popup');
        if (!popup) {
            popup = document.createElement('div');
            popup.id = 'small-popup';
            popup.className = 'small-popup ' + type;
            popup.innerHTML = `<span class="popup-icon">${type==='success' ? '✔️' : '&#9888;'}</span>` +
                              `<span class="popup-text"></span>` +
                              `<span class="popup-close" aria-label="关闭">&times;</span>`;
            // container may not yet be attached to body, but ensureContainer() created it or will append on DOMContentLoaded
            const cont = document.getElementById('small-popup-container') || container;
            try { cont.appendChild(popup); } catch(e) { /* ignore if still not ready */ }
            // close button
            popup.querySelector('.popup-close').addEventListener('click', () => hide(popup));
        } else {
            popup.className = 'small-popup ' + type;
            const icon = popup.querySelector('.popup-icon');
            if (icon) icon.innerHTML = type==='success' ? '✔️' : '&#9888;';
        }

        const textEl = popup.querySelector('.popup-text');
        if (textEl) textEl.textContent = text || '';
        popup.style.display = 'flex';
        // reset animation
        popup.style.animation = 'none';
        // trigger reflow to restart animation
        // eslint-disable-next-line no-unused-expressions
        popup.offsetHeight;
        popup.style.animation = 'fadeInPopup 0.4s';

        if (popup._timer) clearTimeout(popup._timer);
        popup._timer = setTimeout(() => hide(popup), duration);

        function hide(el) {
            try { el.style.display = 'none'; } catch (e) {}
            try { if (el._timer) clearTimeout(el._timer); } catch(e){}
        }
    }

    // expose globally
    window.showSmallPopup = showSmallPopup;
})();
