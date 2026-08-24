(async () => {
  const listEl = document.getElementById('list');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { listEl.innerHTML = '<div class="empty">Sin pestaña activa.</div>'; return; }

  chrome.runtime.sendMessage({ type: 'GET_ALERTS_FOR_TAB', tabId: tab.id }, (alerts) => {
    if (!alerts || alerts.length === 0) {
      listEl.innerHTML = '<div class="empty">Sin patrones sospechosos detectados aún.</div>';
      return;
    }
    listEl.innerHTML = alerts.map(a => `
      <div class="alert">
        <div class="human-msg">⚠️ ${a.explanation || 'Comportamiento sospechoso detectado'}</div>
        <div class="meta">${a.tag}${a.href ? ' → ' + a.href : ''} · confianza: ${(a.score * 100).toFixed(0)}%</div>
        <details>
          <summary>Ver detalle técnico</summary>
          <div class="breakdown">${Object.entries(a.breakdown).map(([k, v]) => `${k}: ${v.toFixed(2)}`).join(' · ')}</div>
        </details>
        ${a.cjsId ? `<button type="button" class="locate-btn" data-cjs-id="${a.cjsId}">📍 Localizar en la página</button>` : ''}
      </div>
    `).join('');

    listEl.querySelectorAll('.locate-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const cjsId = btn.dataset.cjsId;
        chrome.tabs.sendMessage(tab.id, { type: 'LOCATE_ELEMENT', cjsId }, (res) => {
          if (chrome.runtime.lastError || !res?.ok) {
            btn.textContent = '❌ No encontrado';
            btn.disabled = true;
            return;
          }
          btn.textContent = '✓ Localizado';
          setTimeout(() => { btn.textContent = '📍 Localizar en la página'; }, 1500);
        });
      });
    });
  });
})();
