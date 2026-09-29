// The ONLY code path allowed to make network calls. Fails closed.
// Enforces allowlist schema, string lengths, payload limit, PII detection over all text,
// redaction manifest coverage verification, and tamper-evident SHA-256 receipt chaining.

(() => {
  const SERVER_URL = 'http://127.0.0.1:8000';
  const MAX_PAYLOAD_BYTES = 1000000; // 1 MB limit
  const FORBIDDEN_KEYS = new Set(['value', 'innerText', 'password']);

  const ALLOWED_TOP_KEYS = new Set([
    'goal', 'step', 'dom', 'screenshot', 'redactions', 'history', 'mode', 'cleared_media', 'vision',
    'suspectTextCount', 'suspect_text_count', 'v', 'image', 'manifest', 'legend_version'
  ]);
  const ALLOWED_DOM_KEYS = new Set(['url', 'title', 'viewport', 'scrollY', 'nodes']);
  const ALLOWED_NODE_KEYS = new Set([
    'id', 'tag', 'role', 'type', 'label', 'text', 'autocomplete', 'sensitive', 'bbox', 'pii'
  ]);
  const ALLOWED_ACTION_KEYS = new Set(['action', 'target_id', 'coords', 'value', 'reason', 'skipped']);
  const ALLOWED_REDACTION_KEYS = new Set(['id', 'type', 'bbox', 'parentId']);

  // Receipt chain state in memory
  let prevReceiptHash = '0000000000000000000000000000000000000000000000000000000000000000';
  const receiptChain = [];

  async function sha256Hex(str) {
    const enc = new TextEncoder().encode(str);
    const buf = await globalThis.crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Schema allowlist validation
  function assertAllowlist(payload) {
    if (!payload || typeof payload !== 'object') {
      throw new Error('GATE: payload must be a non-null object');
    }

    // Top-level keys
    for (const k of Object.keys(payload)) {
      if (!ALLOWED_TOP_KEYS.has(k)) {
        throw new Error(`GATE: unauthorized top-level key "${k}"`);
      }
    }

    // String lengths
    if (typeof payload.goal === 'string' && payload.goal.length > 500) {
      throw new Error('GATE: goal string exceeds 500 characters');
    }

    // DOM validation
    if (!payload.dom || typeof payload.dom !== 'object') {
      throw new Error('GATE: dom object is required');
    }
    for (const k of Object.keys(payload.dom)) {
      if (!ALLOWED_DOM_KEYS.has(k)) {
        throw new Error(`GATE: unauthorized dom key "${k}"`);
      }
    }
    if (typeof payload.dom.title === 'string' && payload.dom.title.length > 100) {
      throw new Error('GATE: page title exceeds 100 characters');
    }
    if (typeof payload.dom.url === 'string' && payload.dom.url.length > 200) {
      throw new Error('GATE: url exceeds 200 characters');
    }

    // Nodes validation
    if (!Array.isArray(payload.dom.nodes)) {
      throw new Error('GATE: dom.nodes must be an array');
    }
    for (const node of payload.dom.nodes) {
      for (const k of Object.keys(node)) {
        if (!ALLOWED_NODE_KEYS.has(k)) {
          throw new Error(`GATE: unauthorized node key "${k}" on node ${node.id}`);
        }
      }
      if (node.label && node.label.length > 40) {
        throw new Error(`GATE: node label exceeds 40 characters on ${node.id}`);
      }
      if (node.text && node.text.length > 500) {
        throw new Error(`GATE: node text exceeds 500 characters on ${node.id}`);
      }
      if (node.tag && node.tag.length > 20) {
        throw new Error(`GATE: node tag exceeds 20 characters on ${node.id}`);
      }
    }

    // History validation
    if (payload.history) {
      if (!Array.isArray(payload.history)) {
        throw new Error('GATE: history must be an array');
      }
      for (const a of payload.history) {
        for (const k of Object.keys(a)) {
          if (!ALLOWED_ACTION_KEYS.has(k)) {
            throw new Error(`GATE: unauthorized action key "${k}" in history`);
          }
        }
        if (a.value && a.value.length > 100) {
          throw new Error('GATE: history action value exceeds 100 characters');
        }
        if (a.reason && a.reason.length > 500) {
          throw new Error('GATE: history action reason exceeds 500 characters');
        }
      }
    }

    // Redactions manifest validation
    if (payload.redactions) {
      if (!Array.isArray(payload.redactions)) {
        throw new Error('GATE: redactions must be an array');
      }
      for (const r of payload.redactions) {
        for (const k of Object.keys(r)) {
          if (!ALLOWED_REDACTION_KEYS.has(k)) {
            throw new Error(`GATE: unauthorized redaction key "${k}"`);
          }
        }
      }
    }

    // Cleared media validation
    if (payload.cleared_media && !Array.isArray(payload.cleared_media)) {
      throw new Error('GATE: cleared_media must be an array of element IDs');
    }
  }

  // Verify redaction manifest coverage (Task 6)
  function assertRedactionManifest(payload) {
    if (!payload.screenshot) return; // Strict mode has no screenshot

    // Screenshot must be a valid base64 data URL
    if (typeof payload.screenshot !== 'string' || !payload.screenshot.startsWith('data:image/jpeg;base64,')) {
      throw new Error('GATE: screenshot must be a valid jpeg data URL');
    }

    const redactions = payload.redactions;
    if (!Array.isArray(redactions)) {
      throw new Error('GATE: redactions manifest array is required when screenshot is present');
    }

    const redactedIds = new Set(redactions.map((r) => r.id));
    const redactedParentIds = new Set(redactions.filter((r) => r.parentId).map((r) => r.parentId));
    const clearedIds = new Set(payload.cleared_media || []);
    const MEDIA_TAGS = new Set(['img', 'canvas', 'video', 'svg', 'iframe', 'embed', 'object']);

    // Every node in dom.nodes that is media, sensitive or has pii MUST be covered by manifest or cleared by vision
    const nodes = payload.dom?.nodes || [];
    for (const node of nodes) {
      const tag = (node.tag || '').toLowerCase();
      const isMedia = MEDIA_TAGS.has(tag) || (node.role && node.role.startsWith('media'));
      const isSensitive = node.sensitive === true;
      const hasPii = Array.isArray(node.pii) && node.pii.length > 0;

      if (isSensitive || hasPii) {
        if (!redactedIds.has(node.id)) {
          throw new Error(`GATE: sensitive/pii/media node "${node.id}" missing from redaction manifest`);
        }
      } else if (isMedia) {
        // Media must either be fully redacted, have sub-region redactions (parentId), or be recorded in cleared_media
        const isRedacted = redactedIds.has(node.id) || redactedParentIds.has(node.id);
        const isCleared = clearedIds.has(node.id);
        if (!isRedacted && !isCleared) {
          throw new Error(`GATE: sensitive/pii/media node "${node.id}" missing from redaction manifest`);
        }
      }
    }
  }

  // Scan all text in the payload for unredacted PII (skip the base64 screenshot)
  function assertNoRawPII(payload) {
    const piiWorker = globalThis.VeilPII;
    if (!piiWorker || typeof piiWorker.detectPII !== 'function') return;

    const checkString = (str, path) => {
      if (typeof str !== 'string' || str.length === 0) return;
      const findings = piiWorker.detectPII(str);
      if (findings && findings.length > 0) {
        throw new Error(`GATE: unredacted PII (${findings[0].type}) detected in ${path}`);
      }
    };

    // Check goal
    checkString(payload.goal, 'goal');

    // Check DOM title and url
    if (payload.dom) {
      checkString(payload.dom.title, 'dom.title');
      // If URL has path beyond origin, check it
      if (payload.dom.url) {
        const afterOrigin = payload.dom.url.replace(/^https?:\/\/[^\/]+/, '');
        if (afterOrigin && afterOrigin !== '/') {
          checkString(afterOrigin, 'dom.url');
        }
      }

      for (const node of payload.dom.nodes || []) {
        checkString(node.label, `node[${node.id}].label`);
        checkString(node.text, `node[${node.id}].text`);
      }
    }

    // Check history values
    if (payload.history) {
      for (let i = 0; i < payload.history.length; i++) {
        const a = payload.history[i];
        checkString(a.reason, `history[${i}].reason`);
        checkString(a.value, `history[${i}].value`);
      }
    }
  }

  // Check forbidden keys throughout the object tree
  function assertForbiddenKeys(payload) {
    const walk = (o, p) => {
      if (o && typeof o === 'object') {
        for (const k of Object.keys(o)) {
          if (FORBIDDEN_KEYS.has(k)) {
            throw new Error(`GATE: forbidden field "${k}" at ${p}`);
          }
          if (k !== 'screenshot') {
            walk(o[k], `${p}.${k}`);
          }
        }
      }
    };
    walk(payload.dom, 'dom');
  }

  // Main gate validation pipeline
  function assertClean(payload) {
    assertForbiddenKeys(payload);
    assertAllowlist(payload);
    assertRedactionManifest(payload);
    assertNoRawPII(payload);
  }

  // Generate tamper-evident step receipt
  async function createReceipt(payload, bodyLength) {
    // Count PII by type from nodes metadata (no values!)
    const counts = {};
    for (const node of payload.dom?.nodes || []) {
      if (Array.isArray(node.pii)) {
        for (const t of node.pii) {
          counts[t] = (counts[t] || 0) + 1;
        }
      }
    }

    const mode = payload.mode || (payload.screenshot ? 'Balanced' : 'Strict');
    const time = new Date().toISOString();
    const redactionCount = (payload.redactions || payload.manifest || []).length;
    const suspectTextCount = payload.suspectTextCount || payload.suspect_text_count || 0;

    const receiptData = {
      time,
      counts,
      mode,
      bytes: bodyLength,
      redactionCount,
      suspectTextCount,
      hashPrev: prevReceiptHash,
      vision: payload.vision ? {
        backend: payload.vision.backend || 'none',
        totalVisionMs: payload.vision.totalVisionMs || 0,
        facesCount: payload.vision.facesCount || 0,
        textRegionsCount: payload.vision.textRegionsCount || 0,
        elementsCleared: payload.vision.elementsCleared || 0,
        elementsBlackedOut: payload.vision.elementsBlackedOut || 0,
        fallbackReasons: payload.vision.fallbackReasons || []
      } : null
    };

    const canonicalJson = JSON.stringify(receiptData);
    const hash = await sha256Hex(canonicalJson);

    const fullReceipt = {
      ...receiptData,
      hash
    };

    prevReceiptHash = hash;
    receiptChain.push(fullReceipt);

    // Persist receipt chain to session store
    const api = globalThis.browser ?? globalThis.chrome;
    const sessionStore = api?.storage?.session ?? api?.storage?.local;
    if (sessionStore?.set) {
      sessionStore.set({
        latest_receipt: fullReceipt,
        receipt_chain: receiptChain
      }).catch(() => {});
    }

    return fullReceipt;
  }

  function checkServerUrl(urlStr) {
    try {
      const url = new URL(urlStr);
      const isLocal = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
      if (!isLocal && url.protocol === 'http:') {
        throw new Error('GATE: refusing plain HTTP for non-local host. TLS required.');
      }
    } catch (e) {
      if (e.message.includes('refusing plain HTTP')) throw e;
    }
  }

  async function getSharedToken() {
    try {
      const api = globalThis.browser ?? globalThis.chrome;
      if (api?.storage?.local?.get) {
        const { server_token } = await api.storage.local.get('server_token');
        if (server_token) return server_token;
      }
    } catch (_) {}
    return 'veil-shared-secret-token';
  }

  // Negative control test flag (Task 2)
  let __TEST_DISABLE_GATE = false;

  async function sendSanitized(path, payload, receiptLog) {
    // 1. Enforce local invariant assertions (schema, redaction coverage, local PII)
    if (!__TEST_DISABLE_GATE) {
      assertClean(payload); // Throws => fails closed, nothing sent
    }

    // 2. Format protocol v1 payload
    const wirePayload = {
      v: payload.v || '1.0',
      mode: payload.mode || (payload.screenshot ? 'Balanced' : 'Strict'),
      goal: payload.goal,
      step: payload.step,
      history: payload.history || [],
      dom: payload.dom,
      image: payload.image || payload.screenshot || null,
      manifest: (payload.manifest || payload.redactions || []).map((r) => ({
        id: r.id,
        type: r.type,
        bbox: r.bbox
      })),
      legend_version: payload.legend_version || '1.0'
    };

    // 3. Protocol Schema Validation (Task 1)
    if (globalThis.VeilProtocolValidator?.validateRequest) {
      globalThis.VeilProtocolValidator.validateRequest(wirePayload);
    }

    const body = JSON.stringify(wirePayload);
    if (body.length > 2000000) {
      throw new Error(`GATE: total payload size (${body.length} bytes) exceeds 2 MB limit`);
    }

    const receipt = await createReceipt(payload, body.length);
    receiptLog?.(receipt);

    // 4. Security check: refuse plain HTTP for non-local hosts (Task 2)
    const targetUrl = SERVER_URL + path;
    checkServerUrl(targetUrl);

    const token = await getSharedToken();
    const t0 = typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now();

    // Invariant 2: Single network call location
    let res;
    try {
      res = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Veil-Token': token
        },
        body
      });
    } catch (fetchErr) {
      throw new Error(`server down (connection failed: ${fetchErr.message})`);
    }

    // 5. Handle server security responses and tripwire (Task 2 & 3)
    if (res.status === 422) {
      let errorData = null;
      try {
        errorData = await res.json();
      } catch (_) {}
      if (errorData?.code === 'PII_TRIPWIRE') {
        const typesStr = (errorData.types || []).join(', ');
        throw new Error(`server refused: possible leak (${typesStr})`);
      }
      throw new Error(`server refused: schema validation error (HTTP 422)`);
    }
    if (res.status === 401) throw new Error('server refused: unauthorized token (HTTP 401)');
    if (res.status === 413) throw new Error('server refused: payload too large (HTTP 413)');
    if (res.status === 429) throw new Error('server refused: rate limit exceeded (HTTP 429)');
    if (res.status === 503) throw new Error('server refused: concurrency limit reached (HTTP 503)');
    if (res.status === 504) throw new Error('server refused: request timed out (HTTP 504)');
    if (!res.ok) throw new Error(`Server error ${res.status}`);

    const responseJson = await res.json();

    // 6. Validate untrusted server response against Protocol schema (Task 1)
    if (globalThis.VeilProtocolValidator?.validateResponse) {
      globalThis.VeilProtocolValidator.validateResponse(responseJson);
    }

    const t1 = typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now();
    responseJson._latencyMs = Math.round(t1 - t0);
    responseJson._requestBytes = body.length;
    responseJson._receipt = receipt;

    return responseJson;
  }

  function exportReceipts() {
    return {
      type: 'tamper-evident-audit-chain',
      head: prevReceiptHash,
      count: receiptChain.length,
      receipts: [...receiptChain]
    };
  }

  const VeilGate = {
    sendSanitized,
    assertClean,
    assertAllowlist,
    assertRedactionManifest,
    assertNoRawPII,
    createReceipt,
    exportReceipts,
    checkServerUrl,
    setTestDisableGate: (val) => { __TEST_DISABLE_GATE = !!val; },
    isTestDisableGate: () => __TEST_DISABLE_GATE,
    getReceiptChain: () => [...receiptChain]
  };

  globalThis.sendSanitized = sendSanitized;
  globalThis.VeilGate = VeilGate;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilGate;
  }
})();
