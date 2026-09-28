// Veil Protocol Validator (Task 1)
// Enforces shared/protocol.schema.json validation on both sides (Client & Server).
// Rejects unknown fields, oversize strings, and unknown types.
// Dual runtime: Browser extension + Node.js.

(() => {
  const REQUEST_TOP_KEYS = new Set([
    'v', 'mode', 'goal', 'step', 'history', 'dom', 'image', 'manifest', 'legend_version'
  ]);
  const DOM_KEYS = new Set(['url', 'title', 'viewport', 'scrollY', 'nodes']);
  const NODE_KEYS = new Set([
    'id', 'tag', 'role', 'type', 'label', 'text', 'autocomplete', 'sensitive', 'bbox', 'pii'
  ]);
  const MANIFEST_KEYS = new Set(['id', 'type', 'bbox']);
  const HISTORY_KEYS = new Set([
    'type', 'action', 'target_id', 'coords', 'value', 'text', 'question', 'reason'
  ]);

  const ACTION_RESPONSE_KEYS = new Set(['type', 'action', 'target_id', 'coords', 'value', 'reason']);
  const ANSWER_RESPONSE_KEYS = new Set(['type', 'text', 'reason']);
  const ASK_USER_RESPONSE_KEYS = new Set(['type', 'question', 'reason']);
  const DONE_RESPONSE_KEYS = new Set(['type', 'action', 'reason']);
  const FAIL_RESPONSE_KEYS = new Set(['type', 'action', 'reason']);

  const VALID_MODES = new Set(['Strict', 'Balanced']);
  const VALID_ACTIONS = new Set(['click', 'type', 'select', 'scroll']);
  const VALID_RESPONSE_TYPES = new Set(['action', 'answer', 'ask_user', 'done', 'fail']);

  function isInt(val) {
    return typeof val === 'number' && Number.isInteger(val);
  }

  function validateBBox(bbox, name) {
    if (!Array.isArray(bbox) || bbox.length !== 4 || !bbox.every(isInt)) {
      throw new Error(`PROTOCOL: ${name} must be an array of 4 integers [x, y, w, h]`);
    }
  }

  function validateRequest(req) {
    if (!req || typeof req !== 'object' || Array.isArray(req)) {
      throw new Error('PROTOCOL: request must be a non-null object');
    }

    // Top-level key allowlist
    for (const k of Object.keys(req)) {
      if (!REQUEST_TOP_KEYS.has(k)) {
        throw new Error(`PROTOCOL: unauthorized top-level request key "${k}"`);
      }
    }

    // Required fields
    const required = ['v', 'mode', 'goal', 'step', 'history', 'dom', 'manifest', 'legend_version'];
    for (const r of required) {
      if (req[r] === undefined || req[r] === null) {
        throw new Error(`PROTOCOL: missing required request field "${r}"`);
      }
    }

    // v
    if (typeof req.v !== 'string' || !/^[0-9]+(\.[0-9]+)*$/.test(req.v) || req.v.length > 10) {
      throw new Error('PROTOCOL: invalid protocol version "v" (must be semver-like <= 10 chars)');
    }

    // mode
    if (!VALID_MODES.has(req.mode)) {
      throw new Error(`PROTOCOL: invalid mode "${req.mode}" (must be "Strict" or "Balanced")`);
    }

    // goal
    if (typeof req.goal !== 'string' || req.goal.length < 1 || req.goal.length > 500) {
      throw new Error('PROTOCOL: goal must be a string between 1 and 500 characters');
    }

    // step
    if (!isInt(req.step) || req.step < 0 || req.step > 100) {
      throw new Error('PROTOCOL: step must be an integer between 0 and 100');
    }

    // history
    if (!Array.isArray(req.history) || req.history.length > 8) {
      throw new Error('PROTOCOL: history must be an array with max 8 past actions');
    }
    for (let i = 0; i < req.history.length; i++) {
      const h = req.history[i];
      if (!h || typeof h !== 'object' || Array.isArray(h)) {
        throw new Error(`PROTOCOL: history item ${i} must be an object`);
      }
      for (const hk of Object.keys(h)) {
        if (!HISTORY_KEYS.has(hk)) {
          throw new Error(`PROTOCOL: unauthorized key "${hk}" in history item ${i}`);
        }
      }
      if (h.type && (typeof h.type !== 'string' || h.type.length > 20)) {
        throw new Error(`PROTOCOL: history[${i}].type exceeds 20 characters`);
      }
      if (h.action && (typeof h.action !== 'string' || h.action.length > 20)) {
        throw new Error(`PROTOCOL: history[${i}].action exceeds 20 characters`);
      }
      if (h.target_id && (typeof h.target_id !== 'string' || h.target_id.length > 50)) {
        throw new Error(`PROTOCOL: history[${i}].target_id exceeds 50 characters`);
      }
      if (h.value && (typeof h.value !== 'string' || h.value.length > 200)) {
        throw new Error(`PROTOCOL: history[${i}].value exceeds 200 characters`);
      }
      if (h.text && (typeof h.text !== 'string' || h.text.length > 2000)) {
        throw new Error(`PROTOCOL: history[${i}].text exceeds 2000 characters`);
      }
      if (h.question && (typeof h.question !== 'string' || h.question.length > 500)) {
        throw new Error(`PROTOCOL: history[${i}].question exceeds 500 characters`);
      }
      if (h.reason && (typeof h.reason !== 'string' || h.reason.length > 200)) {
        throw new Error(`PROTOCOL: history[${i}].reason exceeds 200 characters`);
      }
      if (h.coords && (!Array.isArray(h.coords) || h.coords.length !== 2 || !h.coords.every(isInt))) {
        throw new Error(`PROTOCOL: history[${i}].coords must be 2 integers`);
      }
    }

    // dom
    const dom = req.dom;
    if (!dom || typeof dom !== 'object' || Array.isArray(dom)) {
      throw new Error('PROTOCOL: dom must be a non-null object');
    }
    for (const dk of Object.keys(dom)) {
      if (!DOM_KEYS.has(dk)) {
        throw new Error(`PROTOCOL: unauthorized dom key "${dk}"`);
      }
    }
    if (typeof dom.url !== 'string' || dom.url.length > 200) {
      throw new Error('PROTOCOL: dom.url must be a string <= 200 characters');
    }
    if (dom.title !== undefined && (typeof dom.title !== 'string' || dom.title.length > 100)) {
      throw new Error('PROTOCOL: dom.title must be a string <= 100 characters');
    }
    if (!Array.isArray(dom.viewport) || dom.viewport.length !== 2 || !dom.viewport.every(isInt)) {
      throw new Error('PROTOCOL: dom.viewport must be an array of 2 integers');
    }
    if (!isInt(dom.scrollY)) {
      throw new Error('PROTOCOL: dom.scrollY must be an integer');
    }
    if (!Array.isArray(dom.nodes) || dom.nodes.length > 1000) {
      throw new Error('PROTOCOL: dom.nodes must be an array <= 1000 items');
    }

    for (let i = 0; i < dom.nodes.length; i++) {
      const node = dom.nodes[i];
      if (!node || typeof node !== 'object' || Array.isArray(node)) {
        throw new Error(`PROTOCOL: dom.nodes[${i}] must be an object`);
      }
      for (const nk of Object.keys(node)) {
        if (!NODE_KEYS.has(nk)) {
          throw new Error(`PROTOCOL: unauthorized node key "${nk}" in dom.nodes[${i}]`);
        }
      }
      if (typeof node.id !== 'string' || node.id.length > 50) {
        throw new Error(`PROTOCOL: node[${i}].id must be a string <= 50 characters`);
      }
      if (typeof node.tag !== 'string' || node.tag.length > 20) {
        throw new Error(`PROTOCOL: node[${i}].tag must be a string <= 20 characters`);
      }
      if (node.role && (typeof node.role !== 'string' || node.role.length > 30)) {
        throw new Error(`PROTOCOL: node[${i}].role must be a string <= 30 characters`);
      }
      if (node.type && (typeof node.type !== 'string' || node.type.length > 30)) {
        throw new Error(`PROTOCOL: node[${i}].type must be a string <= 30 characters`);
      }
      if (node.label !== undefined && (typeof node.label !== 'string' || node.label.length > 100)) {
        throw new Error(`PROTOCOL: node[${i}].label must be a string <= 100 characters`);
      }
      if (node.text && (typeof node.text !== 'string' || node.text.length > 200)) {
        throw new Error(`PROTOCOL: node[${i}].text must be a string <= 200 characters`);
      }
      if (node.autocomplete && (typeof node.autocomplete !== 'string' || node.autocomplete.length > 50)) {
        throw new Error(`PROTOCOL: node[${i}].autocomplete must be a string <= 50 characters`);
      }
      if (typeof node.sensitive !== 'boolean') {
        throw new Error(`PROTOCOL: node[${i}].sensitive must be a boolean`);
      }
      validateBBox(node.bbox, `node[${node.id}].bbox`);
      if (node.pii && (!Array.isArray(node.pii) || !node.pii.every((p) => typeof p === 'string' && p.length <= 30))) {
        throw new Error(`PROTOCOL: node[${i}].pii must be an array of strings <= 30 characters`);
      }
    }

    // image
    if (req.image !== null && req.image !== undefined) {
      if (typeof req.image !== 'string' || req.image.length > 2000000) {
        throw new Error('PROTOCOL: image must be a string <= 2000000 characters');
      }
    }

    // manifest
    if (!Array.isArray(req.manifest) || req.manifest.length > 500) {
      throw new Error('PROTOCOL: manifest must be an array <= 500 items');
    }
    for (let i = 0; i < req.manifest.length; i++) {
      const m = req.manifest[i];
      if (!m || typeof m !== 'object' || Array.isArray(m)) {
        throw new Error(`PROTOCOL: manifest[${i}] must be an object`);
      }
      for (const mk of Object.keys(m)) {
        if (!MANIFEST_KEYS.has(mk)) {
          throw new Error(`PROTOCOL: unauthorized manifest key "${mk}" in item ${i}`);
        }
      }
      if (typeof m.id !== 'string' || m.id.length > 50) {
        throw new Error(`PROTOCOL: manifest[${i}].id must be a string <= 50 characters`);
      }
      if (typeof m.type !== 'string' || m.type.length > 50) {
        throw new Error(`PROTOCOL: manifest[${i}].type must be a string <= 50 characters`);
      }
      validateBBox(m.bbox, `manifest[${i}].bbox`);
    }

    // legend_version
    if (typeof req.legend_version !== 'string' || req.legend_version.length > 20) {
      throw new Error('PROTOCOL: legend_version must be a string <= 20 characters');
    }

    return true;
  }

  function validateResponse(res) {
    if (!res || typeof res !== 'object' || Array.isArray(res)) {
      throw new Error('PROTOCOL: response must be a non-null object');
    }

    // Normalize type if only legacy action is present
    let type = res.type;
    if (!type && res.action) {
      if (res.action === 'done') type = 'done';
      else if (res.action === 'fail') type = 'fail';
      else type = 'action';
    }

    if (!type || !VALID_RESPONSE_TYPES.has(type)) {
      throw new Error(`PROTOCOL: response type must be exactly one of: action | answer | ask_user | done | fail (got "${type}")`);
    }

    // Check reason (required for ALL 5 types, max 200 chars)
    if (typeof res.reason !== 'string' || res.reason.length < 1 || res.reason.length > 200) {
      throw new Error('PROTOCOL: reason is required and must be a string <= 200 characters');
    }

    if (type === 'action') {
      for (const k of Object.keys(res)) {
        if (!ACTION_RESPONSE_KEYS.has(k)) {
          throw new Error(`PROTOCOL: unauthorized key "${k}" in action response`);
        }
      }
      if (!VALID_ACTIONS.has(res.action)) {
        throw new Error(`PROTOCOL: invalid action "${res.action}" (must be click, type, select, or scroll)`);
      }
      if (res.target_id !== undefined && res.target_id !== null && (typeof res.target_id !== 'string' || res.target_id.length > 50)) {
        throw new Error('PROTOCOL: target_id must be a string <= 50 characters');
      }
      if (res.coords !== undefined && res.coords !== null) {
        if (!Array.isArray(res.coords) || res.coords.length !== 2 || !res.coords.every(isInt)) {
          throw new Error('PROTOCOL: coords must be an array of 2 integers');
        }
      }
      if (res.value !== undefined && res.value !== null && (typeof res.value !== 'string' || res.value.length > 200)) {
        throw new Error('PROTOCOL: value must be a string <= 200 characters');
      }
    } else if (type === 'answer') {
      for (const k of Object.keys(res)) {
        if (!ANSWER_RESPONSE_KEYS.has(k)) {
          throw new Error(`PROTOCOL: unauthorized key "${k}" in answer response`);
        }
      }
      if (typeof res.text !== 'string' || res.text.length < 1 || res.text.length > 2000) {
        throw new Error('PROTOCOL: answer text is required and must be a string between 1 and 2000 characters');
      }
    } else if (type === 'ask_user') {
      for (const k of Object.keys(res)) {
        if (!ASK_USER_RESPONSE_KEYS.has(k)) {
          throw new Error(`PROTOCOL: unauthorized key "${k}" in ask_user response`);
        }
      }
      if (typeof res.question !== 'string' || res.question.length < 1 || res.question.length > 500) {
        throw new Error('PROTOCOL: ask_user question is required and must be a string between 1 and 500 characters');
      }
    } else if (type === 'done') {
      for (const k of Object.keys(res)) {
        if (!DONE_RESPONSE_KEYS.has(k)) {
          throw new Error(`PROTOCOL: unauthorized key "${k}" in done response`);
        }
      }
    } else if (type === 'fail') {
      for (const k of Object.keys(res)) {
        if (!FAIL_RESPONSE_KEYS.has(k)) {
          throw new Error(`PROTOCOL: unauthorized key "${k}" in fail response`);
        }
      }
    }

    return true;
  }

  const VeilProtocolValidator = {
    validateRequest,
    validateResponse,
    VALID_MODES,
    VALID_ACTIONS,
    VALID_RESPONSE_TYPES
  };

  globalThis.VeilProtocolValidator = VeilProtocolValidator;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilProtocolValidator;
  }
})();
