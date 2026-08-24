/**
 * Clickjack Sentinel Modificado
 *
 * Arquitectura: cada elemento potencialmente clickeable (<a href>, [onclick],
 * role="button", <button>, <iframe>) se evalúa contra 5 heurísticas.
 * Cada una devuelve un score parcial 0-1; se combinan con pesos en un score
 * final por elemento. Umbral configurable dispara una alerta visual + log.
 *
 * No bloquea nada automáticamente (fase de detección, no de bloqueo activo)
 * para poder calibrar umbrales sin romper sitios legítimos.
 */

function main() {
  console.log("[Clickjack Sentinel] content script cargado en", location.href);

  const CONFIG = {
    SUSPICION_THRESHOLD: 0.55,
    // Un valor <= esto se considera casi invisible.
    OPACITY_SUSPECT_MAX: 0.15, // opacidad por debajo de esto = sospechoso
    SAMPLE_GRID_SIZE: 3, // Rejilla de muestreo espacial.
    MOUSE_FOLLOW_CORR_WINDOW: 12, // muestras de mousemove para medir correlación
    TRANSACTIONAL_WINDOW_MS: 1200, // ventana para detectar aparición/desaparición rápida
    WEIGHTS: {
      shadowing: 0.35, // tapa un elemento visible debajo, siendo invisible y activo
      lowOpacityActive: 0.25, // opacidad casi nula pero pointer-events activo
      crossOriginFrame: 0.15, // iframe de otro origen superpuesto
      mouseFollowing: 0.15, // elemento cuya posición correlaciona con el cursor
      semanticMismatch: 0.1, // texto ancla no relacionado con el dominio del href
    },
    // Patrones que consideramos suficientemente fuertes por sí solos.
    STRONG_SHADOW_THRESHOLD: 0.45,
    STRONG_LOW_OPACITY_THRESHOLD: 0.7,
  };

  const mouseTrail = []; // {x, y, t}
  const domMutationLog = new Map(); // elemento -> [{type, t}]
  const alreadyFlagged = new WeakSet();
  let cjsIdSeq = 0;

  // ---------- Utilidades ----------

  function nextCjsId() {
    cjsIdSeq += 1;
    return `cjs-${Date.now()}-${cjsIdSeq}`;
  }

  function clamp01(v) {
    return Math.max(0, Math.min(1, v));
  }

  function getOpacity(el) {
    const cs = getComputedStyle(el);
    const value = parseFloat(cs.opacity);
    return Number.isFinite(value) ? value : 1;
  }

  function isPointerActive(el) {
    const cs = getComputedStyle(el);
    return (
      cs.pointerEvents !== "none" &&
      cs.visibility !== "hidden" &&
      cs.display !== "none"
    );
  }

  /**
   * Genera una rejilla de puntos dentro del bounding box.
   *
   * Mucho mejor que muestrear únicamente una diagonal porque un
   * overlay de clickjacking puede cubrir solo una parte del elemento.
   */
  function sampleRectPoints(rect, gridSize = CONFIG.SAMPLE_GRID_SIZE) {
    const pts = [];

    if (
      rect.width <= 0 ||
      rect.height <= 0 ||
      !Number.isFinite(rect.width) ||
      !Number.isFinite(rect.height)
    ) {
      return pts;
    }

    for (let ix = 0; ix < gridSize; ix++) {
      for (let iy = 0; iy < gridSize; iy++) {
        const fx = (ix + 0.5) / gridSize;
        const fy = (iy + 0.5) / gridSize;

        pts.push([rect.left + rect.width * fx, rect.top + rect.height * fy]);
      }
    }

    // Centro explícito.
    pts.push([rect.left + rect.width / 2, rect.top + rect.height / 2]);

    return pts;
  }

  function isSentinelOverlay(el) {
    return el instanceof HTMLElement && el.hasAttribute("data-cjs-overlay");
  }

  // Overlay tipo máscara: grande, recibe clicks, y o es un "fantasma"
  // (opacity baja) o está posicionado encima (fixed/absolute / z-index alto).
  function looksLikeOverlay(el) {
    if (!(el instanceof HTMLElement) || isSentinelOverlay(el)) return false;
    const tag = el.tagName;
    if (
      !["DIV", "SPAN", "SECTION", "LABEL", "ASIDE", "ARTICLE"].includes(tag)
    ) {
      return false;
    }
    if (!isPointerActive(el)) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 40 || rect.height < 40) return false;
    const cs = getComputedStyle(el);
    const op = parseFloat(cs.opacity);
    const pos = cs.position;
    const z = parseInt(cs.zIndex, 10);
    return op <= 0.5 || pos === "fixed" || pos === "absolute" || z >= 10;
  }

  function isCrossOriginFrame(el) {
    if (el.tagName !== "IFRAME") return false;
    try {
      // Si esto lanza excepción, es cross-origin (same-origin policy)
      void el.contentWindow.document;
      return false;
    } catch {
      return true;
    }
  }

  function hrefDomain(href) {
    try {
      return new URL(href, location.href).hostname;
    } catch {
      return null;
    }
  }

  function semanticMismatchScore(el) {
    if (el.tagName !== "A" || !el.href) return 0;
    const text = (el.innerText || el.textContent || "").toLowerCase();
    const linkDomain = hrefDomain(el.href);
    const pageDomain = location.hostname;
    if (!linkDomain) return 0;

    // heurística simple: si el dominio del link no es el mismo que la página
    // ni un subdominio, y el texto contiene palabras "de confianza" genéricas
    // (descargar, oficial, pdf, factura, verificar) -> sube sospecha.
    const trustWords = [
      "descargar",
      "oficial",
      "pdf",
      "factura",
      "verificar",
      "seguro",
      "confirmar",
      "documento",
    ];
    const sameSite =
      linkDomain === pageDomain || linkDomain.endsWith("." + pageDomain);
    const hasTrustWord = trustWords.some((w) => text.includes(w));

    if (!sameSite && hasTrustWord) return 0.9;
    if (!sameSite) return 0.3;
    return 0;
  }

  // ---------- Heurística 1: shadowing (el elemento tapa algo visible debajo) ----------
  //
  // La firma real del clickjacking NO es "¿este elemento recibe el evento en su
  // propia posición?" (eso es trivialmente cierto para cualquier elemento en el
  // tope del stack). La firma real es: "¿este elemento es casi invisible, SIGUE
  // recibiendo el evento (pointer-events activo), y justo debajo de él en el mismo
  // punto hay otro elemento claramente visible/prominente?" — es decir, está
  // actuando como una máscara transparente sobre un señuelo visual.

  function shadowingScore(overlay) {
    if (!(overlay instanceof HTMLElement)) {
      return 0;
    }

    const overlayRect = overlay.getBoundingClientRect();

    if (
      overlayRect.width <= 0 ||
      overlayRect.height <= 0 ||
      overlayRect.right <= 0 ||
      overlayRect.bottom <= 0 ||
      overlayRect.left >= innerWidth ||
      overlayRect.top >= innerHeight
    ) {
      return 0;
    }

    const opacity = getOpacity(overlay);

    // Solo nos interesa un overlay que sea difícil de ver.
    if (opacity > 0.5) {
      return 0;
    }

    // Debe poder recibir interacción.
    if (!isPointerActive(overlay)) {
      return 0;
    }

    let bestScore = 0;

    for (const target of targetCandidates) {
      if (!document.contains(target)) {
        targetCandidates.delete(target);
        continue;
      }

      if (target === overlay) {
        continue;
      }

      const importance = visualTargetImportance(target);

      if (importance <= 0) {
        continue;
      }

      const targetRect = target.getBoundingClientRect();

      const intersection = getRectIntersection(overlayRect, targetRect);

      if (!intersection) {
        continue;
      }

      const targetArea = targetRect.width * targetRect.height;

      if (targetArea <= 0) {
        continue;
      }

      // ¿Qué porcentaje del objetivo visible queda cubierto?
      const coverage = intersection.area / targetArea;

      if (coverage <= 0) {
        continue;
      }

      /*
       * Confirmamos que el overlay realmente está encima de esa zona
       * y no solo comparte geometría. Usamos una rejilla (no solo la
       * diagonal) porque un overlay puede cubrir únicamente una
       * esquina o un borde del objetivo, no su centro.
       */

      const samplePoints = sampleRectPoints(intersection);

      let overlayHits = 0;

      for (const [x, y] of samplePoints) {
        if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) {
          continue;
        }

        const stack = document.elementsFromPoint(x, y);

        if (stack[0] === overlay) {
          overlayHits++;
        }
      }

      const topRatio = overlayHits / samplePoints.length;

      if (topRatio === 0) {
        continue;
      }

      /*
       * Score:
       *
       * coverage  -> cuánto del botón se tapa
       * topRatio  -> qué tan frecuentemente el overlay está arriba
       * importance -> qué tan importante parece el objetivo
       */

      const coverageScore = clamp01(coverage);

      const geometricScore = coverageScore * 0.65 + topRatio * 0.35;

      const targetScore = clamp01(geometricScore * importance);

      bestScore = Math.max(bestScore, targetScore);

      /*
       * DEBUG útil durante la calibración.
       */
      console.debug("[Clickjack Sentinel] shadow candidate", {
        overlay,
        target,
        coverage: Number(coverage.toFixed(3)),
        topRatio: Number(topRatio.toFixed(3)),
        importance: Number(importance.toFixed(3)),
        targetScore: Number(targetScore.toFixed(3)),
      });
    }

    return clamp01(bestScore);
  }

  // ---------- Heurística 2: opacidad casi nula pero interactivo ----------
  // ---------- Opacidad + interacción ----------
  function lowOpacityActiveScore(el) {
    const op = getOpacity(el);

    if (!isPointerActive(el)) {
      return 0;
    }

    if (op > CONFIG.OPACITY_SUSPECT_MAX) {
      return 0;
    }

    // 0 opacity -> 1.0
    // 0.15 opacity -> 0.3
    return clamp01(1 - (op / CONFIG.OPACITY_SUSPECT_MAX) * 0.7);
  }

  // ---------- Heurística 3: iframe cross-origin superpuesto y semi-invisible ----------
  function crossOriginFrameScore(el) {
    if (!isCrossOriginFrame(el)) return 0;
    const op = getOpacity(el);
    if (op < 0.9) return 0.6 + (1 - op) * 0.4; // cross-origin + no-full-opacity ya es alarmante
    return 0.2; // cross-origin visible al 100% es normal (ads legítimos, widgets, etc.)
  }

  // ---------- Heurística 4: el elemento sigue al cursor (cursorjacking) ----------

  function mouseFollowingScore(el) {
    if (mouseTrail.length < CONFIG.MOUSE_FOLLOW_CORR_WINDOW) return 0;

    // Necesitamos posiciones históricas del elemento. Las guardamos en un
    // WeakMap externo (positionLog) actualizado por el observer de abajo.
    const history = positionLog.get(el);
    if (!history || history.length < CONFIG.MOUSE_FOLLOW_CORR_WINDOW) return 0;

    const recentMouse = mouseTrail.slice(-CONFIG.MOUSE_FOLLOW_CORR_WINDOW);
    const recentPos = history.slice(-CONFIG.MOUSE_FOLLOW_CORR_WINDOW);
    const n = Math.min(recentMouse.length, recentPos.length);
    if (n < 5) return 0;

    // correlación simple: promedio de distancia normalizada entre deltas
    let corrSum = 0;
    for (let i = 1; i < n; i++) {
      const dMouseX = recentMouse[i].x - recentMouse[i - 1].x;
      const dMouseY = recentMouse[i].y - recentMouse[i - 1].y;
      const dElX = recentPos[i].x - recentPos[i - 1].x;
      const dElY = recentPos[i].y - recentPos[i - 1].y;
      const mouseMag = Math.hypot(dMouseX, dMouseY);
      const elMag = Math.hypot(dElX, dElY);
      if (mouseMag < 1 && elMag < 1) continue; // ambos quietos, no informativo
      const dot = dMouseX * dElX + dMouseY * dElY;
      const cos = mouseMag && elMag ? dot / (mouseMag * elMag) : 0;
      corrSum += Math.max(0, cos);
    }
    return clamp01(corrSum / (n - 1));
  }

  // ---------- Traductor de señales técnicas a explicación humana ----------
  //
  // Idea: dado el vector de scores (breakdown), identifica cuál señal domina
  // y devuelve una frase en español explicando QUÉ está pasando, no solo
  // el número. Esto es lo que verá el usuario final en el popup.

  function explainBreakdown(breakdown) {
    // Encuentra la señal con mayor peso ponderado (no el score crudo,
    // sino score * peso, porque eso refleja cuánto realmente contribuyó
    // al total).
    let topKey = null;
    let topWeighted = -1;
    for (const key in breakdown) {
      const weighted = breakdown[key] * CONFIG.WEIGHTS[key];
      if (weighted > topWeighted) {
        topWeighted = weighted;
        topKey = key;
      }
    }

    // Mapa de explicaciones. TODO: completa 'lowOpacityActive',
    // 'crossOriginFrame', 'mouseFollowing' y 'semanticMismatch'.
    // Pista: pregúntate "si un usuario sin conocimiento técnico viera
    // esto, ¿qué frase corta le ayudaría a entender el riesgo?"
    const explanations = {
      shadowing:
        "Hay un elemento invisible cubriendo algo que parece un botón normal. Tu click podría no ir a donde crees.",
      lowOpacityActive: "Esto existe pero no lo puedes ver",
      crossOriginFrame:
        "Esta parte de la página en realidad pertenece a otro sitio",
      mouseFollowing: "Algo te esta siguiendo o a tu cursor",
      semanticMismatch: "Dice una cosa pero te lleva a otra",
    };

    return (
      explanations[topKey] ||
      "Comportamiento sospechoso detectado (patrón no clasificado aún)."
    );
  }

  // ---------- Score principal ----------
  function computeScore(el) {
    const breakdown = {
      shadowing: shadowingScore(el),
      lowOpacityActive: lowOpacityActiveScore(el),
      crossOriginFrame: crossOriginFrameScore(el),
      mouseFollowing: mouseFollowingScore(el),
      semanticMismatch: semanticMismatchScore(el),
    };

    let total = 0;

    for (const key in breakdown) {
      total += breakdown[key] * CONFIG.WEIGHTS[key];
    }

    total = clamp01(total);

    // Estas se declaran como variables LOCALES primero (no como claves del
    // objeto que retornamos) precisamente para poder reutilizarlas al
    // calcular 'suspicious' más abajo. Un objeto literal no expone sus
    // propias claves como variables dentro de sí mismo.
    const semanticAlone = breakdown.semanticMismatch >= 0.7;

    const strongShadowPattern =
      breakdown.shadowing >= CONFIG.STRONG_SHADOW_THRESHOLD &&
      breakdown.lowOpacityActive >= CONFIG.STRONG_LOW_OPACITY_THRESHOLD;

    const strongIframePattern =
      el.tagName === "IFRAME" &&
      breakdown.lowOpacityActive >= 0.7 &&
      breakdown.shadowing >= 0.35;

    const strongClickjackingPattern =
      el.tagName === "IFRAME" &&
      breakdown.lowOpacityActive >= 0.7 &&
      breakdown.shadowing >= 0.5;

    const suspicious =
      total >= CONFIG.SUSPICION_THRESHOLD ||
      semanticAlone ||
      strongShadowPattern ||
      strongIframePattern;

    return {
      total,
      breakdown,
      strongShadowPattern,
      strongIframePattern,
      strongClickjackingPattern,
      suspicious,
    };
  }

  // ---------- Tracking de posición de elementos candidatos (para heurística de mouse-following) ----------

  const positionLog = new WeakMap();
  const candidates = new Set();
  const targetCandidates = new Set();

  //Así no dependemos de que el “señuelo” sea necesariamente un <button> real; también contemplamos enlaces, roles, onclick, etc.
  //Esto complementa tu collectCandidates(), que actualmente mezcla overlays, iframes y objetivos en el mismo conjunto.
  function collectVisualTargets() {
    const selector = [
      "a[href]",
      "button",
      '[role="button"]',
      "[onclick]",
      'input[type="submit"]',
      'input[type="button"]',
      'input[type="reset"]',
      "div",
      "span",
    ].join(",");

    document.querySelectorAll(selector).forEach((el) => {
      if (!(el instanceof HTMLElement)) return;

      if (
        looksLikeVisualButton(el) ||
        el.matches(
          'a[href], button, [role="button"], [onclick], input[type="submit"], input[type="button"], input[type="reset"]',
        )
      ) {
        targetCandidates.add(el);
      }
    });
  }
  function getRectIntersection(a, b) {
    const left = Math.max(a.left, b.left);
    const top = Math.max(a.top, b.top);
    const right = Math.min(a.right, b.right);
    const bottom = Math.min(a.bottom, b.bottom);

    const width = right - left;
    const height = bottom - top;

    if (width <= 0 || height <= 0) {
      return null;
    }

    return {
      left,
      top,
      right,
      bottom,
      width,
      height,
      area: width * height,
    };
  }

  function looksLikeVisualButton(el) {
    if (!(el instanceof HTMLElement)) {
      return false;
    }

    const text = (el.innerText || el.textContent || "").trim().toLowerCase();

    if (!text) {
      return false;
    }

    const words = [
      "continuar",
      "confirmar",
      "descargar",
      "aceptar",
      "comprar",
      "iniciar",
      "verificar",
      "obtener",
      "seguir",
    ];

    return words.some((word) => text.includes(word));
  }

  function visualTargetImportance(el) {
    if (!(el instanceof HTMLElement)) {
      return 0;
    }

    const rect = el.getBoundingClientRect();

    if (
      rect.right <= 0 ||
      rect.bottom <= 0 ||
      rect.left >= innerWidth ||
      rect.top >= innerHeight
    ) {
      return 0;
    }

    const cs = getComputedStyle(el);

    if (
      cs.display === "none" ||
      cs.visibility === "hidden" ||
      parseFloat(cs.opacity) <= 0.5
    ) {
      return 0;
    }

    switch (el.tagName) {
      case "BUTTON":
        return 1.0;

      case "A":
        return 0.95;

      case "INPUT":
        return 0.95;

      default:
        break;
    }

    if (looksLikeVisualButton(el) && rect.width >= 100 && rect.height >= 30) {
      return 0.75;
    }

    if (el.matches('[role="button"]')) {
      return 0.95;
    }

    if (el.hasAttribute("onclick")) {
      return 0.85;
    }

    return 0.4;
  }

  function collectOverlayHits() {
    // Lo que está realmente encima en el viewport (aunque sea un div sin href).
    const pts = [
      [innerWidth * 0.5, innerHeight * 0.5],
      [innerWidth * 0.25, innerHeight * 0.5],
      [innerWidth * 0.75, innerHeight * 0.5],
      [innerWidth * 0.5, innerHeight * 0.25],
      [innerWidth * 0.5, innerHeight * 0.75],
    ];
    for (const [x, y] of pts) {
      if (x < 0 || y < 0) continue;
      const stack = document.elementsFromPoint(x, y);
      for (const el of stack.slice(0, 5)) {
        if (!(el instanceof HTMLElement) || isSentinelOverlay(el)) continue;
        if (el === document.documentElement || el === document.body) continue;
        const rect = el.getBoundingClientRect();
        if (rect.width >= 40 && rect.height >= 40 && isPointerActive(el)) {
          candidates.add(el);
        }
      }
    }
  }

  function collectCandidates() {
    const selector =
      'a[href], button, [onclick], [role="button"], iframe, input[type="submit"]';

    document.querySelectorAll(selector).forEach((el) => {
      if (!isSentinelOverlay(el)) {
        candidates.add(el);
      }
    });

    document
      .querySelectorAll("div[style], span[style], section[style], label[style]")
      .forEach((el) => {
        if (looksLikeOverlay(el)) {
          candidates.add(el);
        }
      });

    collectVisualTargets();
    collectOverlayHits();
  }

  function trackPositions() {
    candidates.forEach((el) => {
      if (!document.contains(el)) {
        candidates.delete(el);
        positionLog.delete(el);
        return;
      }
      const rect = el.getBoundingClientRect();
      const hist = positionLog.get(el) || [];
      hist.push({ x: rect.left, y: rect.top, t: performance.now() });
      if (hist.length > 30) hist.shift();
      positionLog.set(el, hist);
    });
  }

  document.addEventListener(
    "mousemove",
    (e) => {
      mouseTrail.push({ x: e.clientX, y: e.clientY, t: performance.now() });
      if (mouseTrail.length > 40) mouseTrail.shift();
      trackPositions();
    },
    { passive: true },
  );

  // ---------- Observador de mutaciones (patrón transaccional) ----------

  const mo = new MutationObserver((mutations) => {
    const now = performance.now();
    for (const m of mutations) {
      if (
        m.type === "attributes" &&
        (m.attributeName === "style" || m.attributeName === "class")
      ) {
        const el = m.target;
        if (!(el instanceof HTMLElement)) continue;
        const log = domMutationLog.get(el) || [];
        log.push(now);
        domMutationLog.set(
          el,
          log.filter((t) => now - t < 5000),
        );
      }
      m.addedNodes.forEach((node) => {
        if (node instanceof HTMLElement) collectCandidates();
      });
    }
    collectCandidates();
  });
  mo.observe(document.documentElement, {
    attributes: true,
    childList: true,
    subtree: true,
    attributeFilter: ["style", "class"],
  });

  // ---------- Evaluación periódica + en eventos de click reales ----------
  // ---------- Evaluación ----------
  function evaluateAndReport(el, trigger) {
    const {
      total,
      breakdown,
      strongShadowPattern,
      strongIframePattern,
      strongClickjackingPattern,
      suspicious,
    } = computeScore(el);

    // DEBUG durante calibración
    console.debug("[Clickjack Sentinel]", {
      element: el,
      trigger,
      total: Number(total.toFixed(3)),
      breakdown,
      strongShadowPattern,
      strongIframePattern,
    });

    if (suspicious && !alreadyFlagged.has(el)) {
      alreadyFlagged.add(el);

      reportSuspect(
        el,
        Math.max(
          total,
          breakdown.semanticMismatch,
          strongShadowPattern ? 0.75 : 0,
          strongIframePattern ? 0.8 : 0,
          strongClickjackingPattern ? 0.9 : 0,
        ),
        breakdown,
        trigger,
      );
    }

    return total;
  }

  function reportSuspect(el, score, breakdown, trigger) {
    // Identificador invisible y estable para que el popup pueda localizar
    // este mismo nodo más tarde (data-cjs-id en el DOM).
    if (!el.dataset.cjsId) {
      el.dataset.cjsId = nextCjsId();
    }
    const cjsId = el.dataset.cjsId;

    console.warn("[Clickjack Sentinel] Elemento sospechoso", {
      score: score.toFixed(2),
      trigger,
      breakdown,
      cjsId,
      element: el,
      href: el.href || null,
    });
    highlightElement(el, score);
    chrome.runtime.sendMessage({
      type: "CLICKJACK_ALERT",
      score,
      breakdown,
      explanation: explainBreakdown(breakdown),
      trigger,
      url: location.href,
      tag: el.tagName,
      href: el.href || null,
      cjsId,
    });
  }

  // Recuadro propio (position:fixed), NO en el sospechoso: su opacity:0
  // no puede apagar el highlight. pointer-events:none para no tapar clicks.
  function syncOverlayToEl(box, el) {
    const r = el.getBoundingClientRect();
    box.style.left = `${r.left}px`;
    box.style.top = `${r.top}px`;
    box.style.width = `${Math.max(r.width, 12)}px`;
    box.style.height = `${Math.max(r.height, 12)}px`;
  }

  function mountHighlightBox(el, intense) {
    const box = document.createElement("div");
    box.setAttribute("data-cjs-overlay", intense ? "locate" : "auto");
    box.style.cssText = [
      "position:fixed",
      "pointer-events:none",
      "z-index:2147483647",
      "box-sizing:border-box",
      "border-radius:2px",
      intense
        ? "border:4px solid #ff1744;background:rgba(255,23,68,0.18);box-shadow:0 0 0 6px rgba(255,23,68,0.4),0 0 28px 6px rgba(255,23,68,0.55)"
        : "border:3px dashed rgba(255,0,0,0.95);background:rgba(255,0,0,0.08);box-shadow:0 0 0 2px rgba(255,0,0,0.25)",
    ].join(";");
    syncOverlayToEl(box, el);
    document.documentElement.appendChild(box);
    return box;
  }

  function runHighlight(el, { intense, durationMs }) {
    try {
      el.scrollIntoView({
        behavior: "smooth",
        block: "center",
        inline: "nearest",
      });
    } catch {
      /* elementos detached / SVG extraños */
    }

    const box = mountHighlightBox(el, intense);
    const started = performance.now();
    let on = true;
    let raf = 0;
    let blinkTimer = 0;

    if (intense) {
      blinkTimer = setInterval(() => {
        on = !on;
        box.style.opacity = on ? "1" : "0.22";
      }, 180);
    }

    const tick = () => {
      if (!document.contains(el) || performance.now() - started > durationMs) {
        clearInterval(blinkTimer);
        box.remove();
        return;
      }
      syncOverlayToEl(box, el);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    setTimeout(() => {
      cancelAnimationFrame(raf);
      clearInterval(blinkTimer);
      box.remove();
    }, durationMs + 50);
  }

  function highlightElement(el, _score) {
    runHighlight(el, { intense: false, durationMs: 4000 });
  }

  // Resaltado forzado al localizar desde el popup: parpadeo más agresivo
  // que el highlight automático de detección, para diferenciar la intención.
  function locateHighlight(el) {
    runHighlight(el, { intense: true, durationMs: 2600 });
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type !== "LOCATE_ELEMENT" || !msg.cjsId) return;

    // Solo respondemos si lo encontramos: con all_frames:true varios frames
    // reciben el mensaje y el primero en responder gana. Si un frame vacío
    // contesta not_found antes, anularía un hit válido en un iframe.
    const el = document.querySelector(
      `[data-cjs-id="${CSS.escape(msg.cjsId)}"]`,
    );
    if (!el) return;

    locateHighlight(el);
    sendResponse({ ok: true });
  });

  // Escaneo periódico (para overlays estáticos y cursorjacking, que no
  // requieren de un click real para ser detectados).
  function periodicScan() {
    collectCandidates();
    candidates.forEach((el) => evaluateAndReport(el, "scan"));
  }
  setInterval(periodicScan, 800);

  // Evaluación fina en el momento exacto del evento (útil para el patrón
  // transaccional, que puede vivir menos de 800ms).
  ["mousedown", "mouseup", "click"].forEach((evtName) => {
    document.addEventListener(
      evtName,
      (e) => {
        const path = e.composedPath ? e.composedPath() : [e.target];
        const topEl = path[0];
        if (topEl instanceof HTMLElement) {
          evaluateAndReport(topEl, evtName);
        }
      },
      true,
    ); // captura, para verlo antes que handlers de la página
  });

  collectCandidates();
}
main();
