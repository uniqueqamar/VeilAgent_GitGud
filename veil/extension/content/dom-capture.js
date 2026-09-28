// Builds a sanitized DOM snapshot with stable element IDs and PII redaction.
// RULE: never read input values. Only structure, labels, roles, and boxes.
(() => {
  if (globalThis.__veil_capture_loaded) return;
  globalThis.__veil_capture_loaded = true;

  const api = globalThis.browser ?? globalThis.chrome;
  const idToEl = globalThis.__veil_idToEl ?? new Map();
  const elToId = globalThis.__veil_elToId ?? new WeakMap();
  let counter = globalThis.__veil_counter ?? 0;
  globalThis.__veil_idToEl = idToEl;
  globalThis.__veil_elToId = elToId;

  const CONTROL_SELECTOR = 'button, input, select, textarea, [role=button]';
  const TEXT_SELECTOR = 'h1, h2, h3, h4, h5, h6, p, li, td, th, [role=text]';

  function idFor(el) {
    if (!elToId.has(el)) {
      const id = 'e' + ++counter;
      globalThis.__veil_counter = counter;
      elToId.set(el, id);
      idToEl.set(id, el);
    }
    return elToId.get(el);
  }

  // Scan any string for PII and redact findings in-place
  function scanAndRedact(str) {
    if (!str || typeof str !== 'string') {
      return { text: str || '', piiTypes: [] };
    }
    const piiWorker = globalThis.VeilPII;
    if (!piiWorker || typeof piiWorker.detectPII !== 'function') {
      return { text: str, piiTypes: [] };
    }

    const findings = piiWorker.detectPII(str);
    if (!findings || findings.length === 0) {
      return { text: str, piiTypes: [] };
    }

    const piiTypes = [...new Set(findings.map((f) => f.type))];
    // Sort descending by start index to replace cleanly without offset skew
    const sorted = [...findings].sort((a, b) => b.start - a.start);
    let redacted = str;
    for (const f of sorted) {
      const tag = `[REDACTED:${f.type.toUpperCase()}]`;
      redacted = redacted.slice(0, f.start) + tag + redacted.slice(f.end);
    }
    return { text: redacted, piiTypes };
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

  function isVisible(el) {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  }

  function capture() {
    const nodes = [];
    const seenElements = new Set();

    // 1. Scan form controls and buttons
    document.querySelectorAll(CONTROL_SELECTOR).forEach((el) => {
      if (!isVisible(el)) return;
      seenElements.add(el);
      const r = el.getBoundingClientRect();
      const type = (el.getAttribute('type') || '').toLowerCase();
      const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
      const name = (el.getAttribute('name') || '').toLowerCase();
      const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();

      const rawLabel = labelFor(el);
      const altAttr = el.getAttribute('alt') || '';
      const titleAttr = el.getAttribute('title') || '';

      // Scan all potential string sources
      const redactedLabel = scanAndRedact(rawLabel);
      const redactedAlt = scanAndRedact(altAttr);
      const redactedTitleAttr = scanAndRedact(titleAttr);

      const allPiiTypes = [
        ...new Set([
          ...redactedLabel.piiTypes,
          ...redactedAlt.piiTypes,
          ...redactedTitleAttr.piiTypes
        ])
      ];

      // Use field classifier
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
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute('role') || null,
        type: type || null,
        label: redactedLabel.text.slice(0, 40),
        text: redactedLabel.text.slice(0, 200),
        autocomplete: ac || null,
        sensitive: isSensitive,
        pii: allPiiTypes,
        bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
      });
    });

    // 2. Scan visible text blocks (headings, paragraphs, list items, table cells)
    // Max 200 chars per block; never input values
    document.querySelectorAll(TEXT_SELECTOR).forEach((el) => {
      if (seenElements.has(el) || !isVisible(el)) return;
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') return;

      const rawText = (el.innerText || el.textContent || '').trim().replace(/\s+/g, ' ');
      if (!rawText || rawText.length === 0) return;

      const boundedText = rawText.slice(0, 200);
      const redacted = scanAndRedact(boundedText);

      const r = el.getBoundingClientRect();
      nodes.push({
        id: idFor(el),
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute('role') || 'text',
        type: null,
        label: '',
        text: redacted.text,
        autocomplete: null,
        sensitive: redacted.piiTypes.length > 0,
        pii: redacted.piiTypes,
        bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
      });
    });

    // 3. Scan media elements and elements with CSS background-image (redact-by-default)
    const MEDIA_SELECTOR = 'img, canvas, video, svg, iframe, embed, object';
    document.querySelectorAll(MEDIA_SELECTOR).forEach((el) => {
      if (seenElements.has(el) || !isVisible(el)) return;
      seenElements.add(el);
      const r = el.getBoundingClientRect();
      const alt = el.getAttribute('alt') || el.getAttribute('title') || el.getAttribute('aria-label') || '';
      const redactedAlt = scanAndRedact(alt);
      nodes.push({
        id: idFor(el),
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute('role') || 'media',
        type: null,
        label: redactedAlt.text.slice(0, 40),
        text: null,
        autocomplete: null,
        sensitive: true,
        pii: redactedAlt.piiTypes,
        bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
      });
    });

    document.querySelectorAll('div, section, header, main, aside, span').forEach((el) => {
      if (seenElements.has(el) || !isVisible(el)) return;
      const s = getComputedStyle(el);
      if (s.backgroundImage && s.backgroundImage !== 'none') {
        seenElements.add(el);
        const r = el.getBoundingClientRect();
        nodes.push({
          id: idFor(el),
          tag: el.tagName.toLowerCase(),
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

    // Scan page title and URL path pieces
    const titleScan = scanAndRedact(document.title || '');
    const pathScan = scanAndRedact(location.pathname || '');

    const originOnly = location.origin && location.origin !== 'null'
      ? location.origin
      : (location.protocol + '//');

    return {
      url: originOnly,
      title: titleScan.text,
      viewport: [innerWidth, innerHeight],
      scrollY: Math.round(scrollY),
      nodes
    };
  }

  function getMetricsAndBoxes() {
    const boxes = [];
    const ALL_SELECTOR = 'button, input, select, textarea, [role=button], img, canvas, video, svg, iframe, embed, object, h1, h2, h3, h4, h5, h6, p, li, td, th';
    document.querySelectorAll(ALL_SELECTOR).forEach((el) => {
      if (!isVisible(el)) return;
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
      boxes
    };
  }

  globalThis.__veil = { capture, idToEl, scanAndRedact, getMetricsAndBoxes };

  api.runtime.onMessage.addListener((msg, _s, reply) => {
    if (msg?.type === 'CAPTURE') reply({ ok: true, dom: capture() });
    if (msg?.type === 'GET_METRICS_AND_BOXES') reply(getMetricsAndBoxes());
  });
})();


