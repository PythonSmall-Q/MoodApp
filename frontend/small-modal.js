// small-modal.js
// Provides showModalPrompt(message, defaultValue) and showModalConfirm(message)
(function(){
    if (window._smallModalInit) return;
    window._smallModalInit = true;

    const css = document.createElement('style');
    css.textContent = `
    .modal-backdrop { position: fixed; left:0; top:0; right:0; bottom:0; background: rgba(0,0,0,0.35); display:flex; align-items:center; justify-content:center; z-index:10050; }
    .modal-card { background:#fff; border-radius:10px; padding:18px 20px; max-width:600px; width:90%; box-shadow:0 8px 40px rgba(0,0,0,0.18); }
    .modal-title { font-size:1.05rem; color:#3a7afe; font-weight:700; margin-bottom:8px; }
    .modal-body { margin-bottom:12px; color:#222; }
    .modal-actions { display:flex; gap:8px; justify-content:flex-end; }
    .modal-input { width:100%; padding:8px 10px; border:1px solid #e3eafc; border-radius:8px; font-size:0.95rem; }
    .modal-btn { padding:8px 14px; border-radius:8px; font-weight:600; cursor:pointer; border:none; }
    .modal-btn.primary { background: linear-gradient(90deg,#3a7afe 0%,#0056b3 100%); color:#fff; }
    .modal-btn.ghost { background:#f7f9ff; color:#3a7afe; border:1px solid #e3eafc; }
    `;
    document.head.appendChild(css);

    function createBackdrop() {
        const bd = document.createElement('div'); bd.className = 'modal-backdrop';
        const card = document.createElement('div'); card.className = 'modal-card';
        bd.appendChild(card);
        return { bd, card };
    }

    function showModalPrompt(message, defaultValue) {
        return new Promise((resolve) => {
            const { bd, card } = createBackdrop();
            const MAX_LEN = 200;
            card.innerHTML = `<div class="modal-title">${escapeHtml(message)}</div>` +
                `<div class="modal-body"><input class="modal-input" id="_modal_input" maxlength="${MAX_LEN}" value="${escapeAttr(defaultValue || '')}" />`+
                `<div id="_modal_count" style="text-align:right;font-size:0.85rem;color:#666;margin-top:6px;">${MAX_LEN}</div></div>` +
                `<div class="modal-actions"><button class="modal-btn ghost" id="_modal_cancel">取消</button><button class="modal-btn primary" id="_modal_ok">确定</button></div>`;
            document.body.appendChild(bd);
            const input = card.querySelector('#_modal_input');
            const ok = card.querySelector('#_modal_ok');
            const cancel = card.querySelector('#_modal_cancel');
            const countEl = card.querySelector('#_modal_count');
            // initialize counter
            if (countEl) countEl.textContent = String(MAX_LEN - (input.value||'').length);
            input.addEventListener('input', () => {
                try { if (countEl) countEl.textContent = String(MAX_LEN - (input.value||'').length); } catch(e){}
            });
            input.focus(); input.select();
            function close(val) { try { bd.remove(); } catch(e){} resolve(val); }
            ok.onclick = () => close(String(input.value || ''));
            cancel.onclick = () => close(null);
            bd.addEventListener('click', (e) => { if (e.target === bd) close(null); });
            document.addEventListener('keydown', function escHandler(e){ if (e.key === 'Escape') { close(null); document.removeEventListener('keydown', escHandler); } if (e.key === 'Enter' && document.activeElement === input) { close(String(input.value || '')); document.removeEventListener('keydown', escHandler); } });
        });
    }

    function showModalConfirm(message) {
        return new Promise((resolve) => {
            const { bd, card } = createBackdrop();
            card.innerHTML = `<div class="modal-title">${escapeHtml(message)}</div>` +
                `<div class="modal-body"></div>` +
                `<div class="modal-actions"><button class="modal-btn ghost" id="_modal_cancel">取消</button><button class="modal-btn primary" id="_modal_ok">确定</button></div>`;
            document.body.appendChild(bd);
            const ok = card.querySelector('#_modal_ok');
            const cancel = card.querySelector('#_modal_cancel');
            function close(val) { try { bd.remove(); } catch(e){} resolve(val); }
            ok.onclick = () => close(true);
            cancel.onclick = () => close(false);
            bd.addEventListener('click', (e) => { if (e.target === bd) close(false); });
            document.addEventListener('keydown', function escHandler(e){ if (e.key === 'Escape') { close(false); document.removeEventListener('keydown', escHandler); } if (e.key === 'Enter') { close(true); document.removeEventListener('keydown', escHandler); } });
        });
    }

    function escapeHtml(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    function escapeAttr(s) { return String(s || '').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }

    window.showModalPrompt = showModalPrompt;
    window.showModalConfirm = showModalConfirm;
})();
