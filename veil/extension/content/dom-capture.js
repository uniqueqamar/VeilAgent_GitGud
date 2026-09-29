// Builds a sanitized DOM snapshot with stable element IDs, shadow DOM traversal,
// visibility verification, anti-clickjacking guards, and PII redaction.
// RULE: never read input values. Only structure, labels, roles, and boxes.
// RULE: never inject elements into page DOM.
(() => {
  if (globalThis.__veil_capture_loaded) return;
  globalThis.__veil_capture_loaded = true;

  const api = globalThis.browser ?? globalThis.chrome;
  const idToEl = globalThis.__veil_idToEl ?? new Map();
  const elToId = globalThis.__veil_elToId ?? new WeakMap();
  let counter = globalThis.__veil_counter ?? 0;
  globalThis.__veil_idToEl = idToEl;
  globalThis.__veil_elToId = elToId;

  // Debounced MutationObserver for dynamic page stability (Task 4)
  let lastMutationTime = Date.now();
  try {
    const observer = new MutationObserver(() => {
      lastMutationTime = Date.now();
    });
    if (document.documentElement || document.body) {
      observer.observe(document.documentElement || document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true
      });
    }
  } catch (_) {}

  const CONTROL_TAGS = new Set(['button', 'input', 'select', 'textarea']);
  const TEXT_TAGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'li', 'td', 'th']);
  const MEDIA_TAGS = new Set(['img', 'canvas', 'video', 'svg', 'iframe', 'embed', 'object']);

  function idFor(el) {
    if (!elToId.has(el)) {
      const id = 'e' + ++counter;
      globalThis.__veil_counter = counter;
      elToId.set(el, id);
      idToEl.set(id, el);
    }
    return elToId.get(el);
  }

  // Scan any string for PII and redact findings in-place (incorporates Injection Shield)
  function scanAndRedact(str) {
    if (!str || typeof str !== 'string') {
      return { text: str || '', piiTypes: [], suspectCount: 0 };
    }

    // Task 3: Run Injection Shield (strip zero-width/bidi, mask instruction text)
    let sanitizedStr = str;
    let suspectCount = 0;
    const shield = globalThis.VeilInjectionShield || (typeof require !== 'undefined' ? require('../privacy/injection-shield.js') : null);
    if (shield && typeof shield.sanitizeText === 'function') {
      const shieldRes = shield.sanitizeText(str);
      sanitizedStr = shieldRes.text;
      suspectCount = shieldRes.suspectCount || 0;
    }

    const piiWorker = globalThis.VeilPII;
    if (!piiWorker || typeof piiWorker.detectPII !== 'function') {
      return { text: sanitizedStr, piiTypes: [], suspectCount };
    }

    const findings = piiWorker.detectPII(sanitizedStr);
    if (!findings || findings.length === 0) {
      return { text: sanitizedStr, piiTypes: [], suspectCount };
    }

    const piiTypes = [...new Set(findings.map((f) => f.type))];
    const sorted = [...findings].sort((a, b) => b.start - a.start);
    let redacted = sanitizedStr;
    for (const f of sorted) {
      const tag = `[REDACTED:${f.type.toUpperCase()}]`;
      redacted = redacted.slice(0, f.start) + tag + redacted.slice(f.end);
    }
    return { text: redacted, piiTypes, suspectCount };
  }

  // Relative luminance for WCAG contrast calculation (Task 5)
  function getLuminance(r, g, b) {
    const a = [r, g, b].map((v) => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
  }

  function parseColor(str) {
    if (!str || typeof str !== 'string') return null;
    const m = str.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    if (m) return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
    return null;
  }

  function getContrastRatio(colorStr, bgStr) {
    const c1 = parseColor(colorStr);
    const c2 = parseColor(bgStr);
    if (!c1 || !c2) return 21; // Assume sufficient if cannot parse
    const l1 = getLuminance(c1[0], c1[1], c1[2]);
    const l2 = getLuminance(c2[0], c2[1], c2[2]);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
  }

  // VISIBLE-TEXT-ONLY and legitimate rendering verification (Task 5)
  // Excludes: display:none, visibility:hidden, opacity < 0.05, off-screen,
  // font-size < 6px, contrast < 1.5, aria-hidden, clipped or 1px, negative text-indent.
  function isVisibleAndLegible(el) {
    if (!el || el.nodeType !== 1) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);

    // 1. display: none
    if (s.display === 'none') return false;

    // 2. visibility: hidden or collapse
    if (s.visibility === 'hidden' || s.visibility === 'collapse') return false;

    // 3. opacity below 0.05
    const op = parseFloat(s.opacity);
    if (!isNaN(op) && op < 0.05) return false;

    // 4. Off-screen / zero dimensions
    if (r.width <= 0 || r.height <= 0) return false;
    if (r.right < -100 || r.bottom < -100 || r.left > window.innerWidth + 5000 || r.top > window.innerHeight + 5000) {
      return false;
    }

    // 5. font-size under 6px
    const fs = parseFloat(s.fontSize);
    if (!isNaN(fs) && fs < 6) return false;

    // 6. Text color nearly equal to background (contrast under 1.5)
    let effectiveBg = s.backgroundColor;
    let curr = el.parentElement;
    while (curr && (!effectiveBg || effectiveBg === 'transparent' || effectiveBg === 'rgba(0, 0, 0, 0)')) {
      effectiveBg = getComputedStyle(curr).backgroundColor;
      curr = curr.parentElement;
    }
    if (!effectiveBg || effectiveBg === 'transparent' || effectiveBg === 'rgba(0, 0, 0, 0)') {
      effectiveBg = 'rgb(255, 255, 255)';
    }
    if (s.color && getContrastRatio(s.color, effectiveBg) < 1.5) {
      return false;
    }

    // 7. aria-hidden
    if (el.getAttribute('aria-hidden') === 'true' || el.closest?.('[aria-hidden="true"]')) {
      return false;
    }

    // 8. Clipped or 1px elements
    if (r.width <= 1 || r.height <= 1) return false;
    if (s.clip && (s.clip.includes('rect(0px, 0px, 0px, 0px)') || s.clip.includes('rect(0, 0, 0, 0)'))) return false;
    if (s.clipPath && (s.clipPath.includes('polygon(0px 0px') || s.clipPath.includes('inset(50%)') || s.clipPath === 'circle(0px)')) return false;

    // 9. Large negative text-indent (e.g. -9999px)
    const ti = parseInt(s.textIndent, 10);
    if (!isNaN(ti) && ti <= -100) return false;

    return true;
  }

  // Clickjacking overlay check (Task 6)
  function isCoveredByOverlay(el, r) {
    const cx = Math.round(r.left + r.width / 2);
    const cy = Math.round(r.top + r.height / 2);
    if (cx < 0 || cy < 0 || cx > window.innerWidth || cy > window.innerHeight) {
      return false;
    }
    try {
      const topEl = document.elementFromPoint(cx, cy);
      if (topEl && topEl !== el && !el.contains(topEl) && !topEl.contains(el)) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  function labelFor(el) {
    let lbl = '';
    if (el.labels && el.labels[0]) {
      lbl = el.labels[0].innerText || el.labels[0].textContent || '';
    } else {
      lbl =
        el.getAttribute('aria-label') ||
        el.getAttribute('placeholder') ||
        el.getAttribute('title') ||
        el.getAttribute('alt') ||
        el.getAttribute('name') ||
        '';
      if (!lbl && (el.tagName === 'BUTTON' || el.getAttribute('role') === 'button')) {
        lbl = el.innerText || el.textContent || '';
      } else if (!lbl && el.tagName === 'INPUT' && (el.type === 'button' || el.type === 'submit')) {
        lbl = el.getAttribute('value') || '';
      }
    }
    return (lbl || '').trim().replace(/\s+/g, ' ').slice(0, 200);
  }

  // Recursive tree walker supporting OPEN Shadow DOM (Task 3)
  function walkElements(root, callback, depth = 0) {
    if (!root || depth > 20) return;
    const children = root.children || root.childNodes || [];
    for (let i = 0; i < children.length; i++) {
      const node = children[i];
      if (node.nodeType === 1) { // ELEMENT_NODE
        callback(node);

        // Traverse OPEN shadow roots (Task 3)
        if (node.shadowRoot) {
          walkElements(node.shadowRoot, callback, depth + 1);
        }

        walkElements(node, callback, depth + 1);
      }
    }
  }

  function isClosedOrOpaqueWidget(el) {
    const tag = el.tagName.toLowerCase();
    // Custom elements without open shadow root, or canvas/embed/object
    const isCustomElement = tag.includes('-') && !el.shadowRoot;
    const isOpaqueTag = ['canvas', 'embed', 'object'].includes(tag);
    return isCustomElement || isOpaqueTag;
  }

  // Capture current frame's sanitized DOM
  function capture(options = {}) {
    const frameId = options.frameId ?? 0;
    const isOpenMode = options.mode === 'Open';
    const textLimit = isOpenMode ? 500 : 200;
    const maxNodes = isOpenMode ? 800 : 400;
    let totalSuspectTextCount = 0;

    const nodes = [];
    const seenElements = new Set();
    const childFrames = [];

    walkElements(document.documentElement || document.body, (el) => {
      if (seenElements.has(el)) return;

      const tag = el.tagName.toLowerCase();
      const role = el.getAttribute('role') || '';

      // Track child iframes (Task 1 & 2)
      if (tag === 'iframe' || tag === 'frame') {
        const r = el.getBoundingClientRect();
        let srcOrigin = '';
        try {
          if (el.src) {
            const u = new URL(el.src, window.location.href);
            srcOrigin = u.origin;
          }
        } catch (_) {}
        childFrames.push({
          id: el.id || '',
          name: el.name || '',
          srcOrigin: srcOrigin || 'about:blank',
          bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
        });
      }

      // Check Closed Shadow DOM or Opaque Widgets (Task 3: treated like media)
      if (isClosedOrOpaqueWidget(el)) {
        if (!isVisibleAndLegible(el)) return;
        seenElements.add(el);
        const r = el.getBoundingClientRect();
        nodes.push({
          id: idFor(el),
          tag,
          role: 'opaque_widget',
          type: null,
          label: (el.getAttribute('aria-label') || el.id || tag).slice(0, 40),
          text: null,
          autocomplete: null,
          sensitive: true, // Invariant 10: stays solid black unless vision clears it
          pii: [],
          bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
        });
        return;
      }

      // 1. Form controls and interactive buttons
      const isControl = CONTROL_TAGS.has(tag) || role === 'button' || el.hasAttribute('onclick');
      if (isControl) {
        if (!isVisibleAndLegible(el)) return;
        const r = el.getBoundingClientRect();
        // Clickjacking overlay check (Task 6)
        if (isCoveredByOverlay(el, r)) return;

        seenElements.add(el);
        const type = (el.getAttribute('type') || '').toLowerCase();
        const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
        const name = (el.getAttribute('name') || '').toLowerCase();
        const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();

        const rawLabel = labelFor(el);
        const altAttr = el.getAttribute('alt') || '';
        const titleAttr = el.getAttribute('title') || '';

        const redactedLabel = scanAndRedact(rawLabel);
        const redactedAlt = scanAndRedact(altAttr);
        const redactedTitleAttr = scanAndRedact(titleAttr);
        totalSuspectTextCount += (redactedLabel.suspectCount || 0) + (redactedAlt.suspectCount || 0) + (redactedTitleAttr.suspectCount || 0);

        const allPiiTypes = [
          ...new Set([
            ...redactedLabel.piiTypes,
            ...redactedAlt.piiTypes,
            ...redactedTitleAttr.piiTypes
          ])
        ];

        const nodeInfo = {
          type,
          autocomplete: ac,
          name,
          id: el.id || '',
          label: rawLabel,
          placeholder
        };
        const classification = globalThis.VeilPII?.classifyField
          ? globalThis.VeilPII.classifyField(nodeInfo)
          : { sensitive: false, pii_type: null };

        if (classification.pii_type && !allPiiTypes.includes(classification.pii_type)) {
          allPiiTypes.push(classification.pii_type);
        }

        const isSensitive =
          classification.sensitive ||
          type === 'password' ||
          /cc-|one-time-code/.test(ac) ||
          allPiiTypes.length > 0;

        nodes.push({
          id: idFor(el),
          tag,
          role: role || null,
          type: type || null,
          label: redactedLabel.text.slice(0, 100),
          text: redactedLabel.text.slice(0, textLimit),
          autocomplete: ac || null,
          sensitive: isSensitive,
          pii: allPiiTypes,
          bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
        });
        return;
      }

      // 2. Visible text blocks (headings, paragraphs, lists, table cells)
      const isText = TEXT_TAGS.has(tag) || role === 'text';
      if (isText) {
        if (!isVisibleAndLegible(el)) return;
        seenElements.add(el);
        const rawText = (el.innerText || el.textContent || '').trim().replace(/\s+/g, ' ');
        if (!rawText || rawText.length === 0) return;

        const boundedText = rawText.slice(0, textLimit);
        const redacted = scanAndRedact(boundedText);
        totalSuspectTextCount += redacted.suspectCount || 0;
        const r = el.getBoundingClientRect();

        nodes.push({
          id: idFor(el),
          tag,
          role: role || 'text',
          type: null,
          label: '',
          text: redacted.text,
          autocomplete: null,
          sensitive: redacted.piiTypes.length > 0,
          pii: redacted.piiTypes,
          bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
        });
        return;
      }

      // 3. Media elements (img, canvas, video, svg, iframe...)
      if (MEDIA_TAGS.has(tag)) {
        if (!isVisibleAndLegible(el)) return;
        seenElements.add(el);
        const r = el.getBoundingClientRect();
        const alt = el.getAttribute('alt') || el.getAttribute('title') || el.getAttribute('aria-label') || '';
        const redactedAlt = scanAndRedact(alt);
        totalSuspectTextCount += redactedAlt.suspectCount || 0;

        nodes.push({
          id: idFor(el),
          tag,
          role: role || 'media',
          type: null,
          label: redactedAlt.text.slice(0, 40),
          text: null,
          autocomplete: null,
          sensitive: true, // Invariant 10: Media stays solid black by default
          pii: redactedAlt.piiTypes,
          bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
        });
        return;
      }

      // 4. Background images
      const s = getComputedStyle(el);
      if (s.backgroundImage && s.backgroundImage !== 'none') {
        if (!isVisibleAndLegible(el)) return;
        seenElements.add(el);
        const r = el.getBoundingClientRect();
        nodes.push({
          id: idFor(el),
          tag,
          role: 'media_background',
          type: null,
          label: '',
          text: null,
          autocomplete: null,
          sensitive: true,
          pii: [],
          bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
        });
      }
    });

    // Viewport-first sorting (Task 1 & 4)
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    nodes.sort((a, b) => {
      const aInView = a.bbox[0] >= 0 && a.bbox[1] >= 0 && a.bbox[0] < vw && a.bbox[1] < vh;
      const bInView = b.bbox[0] >= 0 && b.bbox[1] >= 0 && b.bbox[0] < vw && b.bbox[1] < vh;
      if (aInView && !bInView) return -1;
      if (!aInView && bInView) return 1;
      return 0;
    });

    // Cap nodes (Open mode: 800, Balanced/Strict: 400)
    const cappedNodes = nodes.slice(0, maxNodes);

    const titleScan = scanAndRedact(document.title || '');
    totalSuspectTextCount += titleScan.suspectCount || 0;
    const originOnly = location.origin && location.origin !== 'null'
      ? location.origin
      : (location.protocol + '//' + location.host);

    return {
      isTop: window === window.top,
      origin: originOnly,
      url: originOnly,
      title: titleScan.text,
      viewport: [innerWidth, innerHeight],
      scrollY: Math.round(scrollY),
      nodes: cappedNodes,
      childFrames,
      suspectTextCount: totalSuspectTextCount
    };
  }

  function getMetricsAndBoxes() {
    const boxes = [];
    walkElements(document.documentElement || document.body, (el) => {
      if (!isVisibleAndLegible(el)) return;
      const r = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      const hasBgImage = style.backgroundImage && style.backgroundImage !== 'none';
      const type = (el.getAttribute('type') || '').toLowerCase();
      const ac = (el.getAttribute('autocomplete') || '').toLowerCase();

      boxes.push({
        id: idFor(el),
        tag: el.tagName.toLowerCase(),
        sensitive: type === 'password' || /cc-|one-time-code/.test(ac),
        hasBgImage,
        bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
      });
    });

    return {
      scrollX: Math.round(window.scrollX || window.pageXOffset || 0),
      scrollY: Math.round(window.scrollY || window.pageYOffset || 0),
      dpr: window.devicePixelRatio || 1,
      viewport: [window.innerWidth, window.innerHeight],
      boxes: boxes.slice(0, 400)
    };
  }

  // Export internal API strictly on globalThis for extension worker access
  globalThis.__veil = {
    capture,
    idToEl,
    elToId,
    scanAndRedact,
    getMetricsAndBoxes,
    isVisibleAndLegible
  };

  // Content script communication (Never accepts window.postMessage from page)
  api.runtime.onMessage.addListener((msg, sender, reply) => {
    if (msg?.type === 'CAPTURE') {
      reply({ ok: true, dom: capture(msg) });
    }
    if (msg?.type === 'GET_METRICS_AND_BOXES') {
      reply(getMetricsAndBoxes());
    }
  });
})();
