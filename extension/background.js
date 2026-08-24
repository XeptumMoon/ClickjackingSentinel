// Guarda las últimas alertas por pestaña para mostrarlas en el popup.
//
// IMPORTANTE #1: en Manifest V3 este archivo NO corre de forma continua.
// Chrome apaga este "service worker" tras ~30s de inactividad y lo vuelve
// a arrancar desde cero cuando lo necesita. Cualquier variable normal de
// JS declarada aquí arriba se pierde en ese apagado — por eso usamos
// chrome.storage.session para el contenido real de las alertas.
//
// IMPORTANTE #2 (el bug que corregimos aquí): chrome.storage es asíncrono.
// Si dos alertas llegan casi al mismo tiempo (ej. el escaneo periódico
// detecta 2 elementos sospechosos en el mismo tick), ambas pueden LEER
// la lista antes de que la primera termine de ESCRIBIR — la segunda
// escritura sobreescribe a la primera y se pierde una alerta. Esto es
// una condición de carrera (race condition) clásica de lectura-modificación-
// escritura sin exclusión mutua.
//
// La solución: una cola de promesas por pestaña (writeQueues). Cada nueva
// alerta se encadena DESPUÉS de que la anterior para esa misma pestaña
// termine, garantizando que nunca se solapen lectura/escritura.

const KEY_PREFIX = 'alerts_tab_';
const writeQueues = new Map(); // tabId -> promesa de la última operación encolada

async function getAlerts(tabId) {
  const key = KEY_PREFIX + tabId;
  const result = await chrome.storage.session.get(key);
  return result[key] || [];
}

async function setAlerts(tabId, list) {
  const key = KEY_PREFIX + tabId;
  await chrome.storage.session.set({ [key]: list });
}

async function clearAlerts(tabId) {
  const key = KEY_PREFIX + tabId;
  writeQueues.delete(tabId);
  await chrome.storage.session.remove(key);
}

// Encola la operación de agregar una alerta, garantizando que se ejecute
// DESPUÉS de cualquier operación pendiente anterior para la misma pestaña.
function enqueueAlert(tabId, alertData) {
  const previous = writeQueues.get(tabId) || Promise.resolve();

  const next = previous
    .catch(() => {}) // si la anterior falló, no bloquear la cola por eso
    .then(async () => {
      const list = await getAlerts(tabId);
      list.unshift(alertData);
      const trimmed = list.slice(0, 50);
      await setAlerts(tabId, trimmed);

      chrome.action.setBadgeText({ text: String(trimmed.length), tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#c62828', tabId });
    });

  writeQueues.set(tabId, next);
  return next;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'CLICKJACK_ALERT') {
    const tabId = sender.tab ? sender.tab.id : 'unknown';
    enqueueAlert(tabId, { ...msg, time: Date.now() });
    return;
  }

  if (msg.type === 'GET_ALERTS_FOR_TAB') {
    (async () => {
      // Espera a que termine cualquier escritura pendiente para esta pestaña
      // antes de leer, para no devolver un estado a medio escribir.
      const pending = writeQueues.get(msg.tabId);
      if (pending) await pending.catch(() => {});
      const list = await getAlerts(msg.tabId);
      sendResponse(list);
    })();
    return true; // indica a Chrome que sendResponse llegará de forma asíncrona
  }
});

chrome.tabs.onRemoved.addListener((tabId) => clearAlerts(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading') {
    clearAlerts(tabId);
    chrome.action.setBadgeText({ text: '', tabId });
  }
});
