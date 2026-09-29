// Agent orchestrator for Veil Agent
// Coordinates: capture -> redact -> gate -> server -> validate -> execute -> repeat.
// Strictly obeys invariants: no PII values sent, vault encrypted, unverified redaction degrades to Strict.

if (typeof importScripts === 'function') {
  try {
    importScripts('/workers/pii.js', '/workers/field-matcher.js', '/privacy/injection-shield.js', '/privacy/protocol-validator.js', '/privacy/vault.js', '/privacy/model-loader.js', '/privacy/vision-runner.js', '/privacy/redactor.js', '/privacy/gate.js');
  } catch (e) {
    try {
      importScripts('../workers/pii.js', '../workers/field-matcher.js', '../privacy/injection-shield.js', '../privacy/protocol-validator.js', '../privacy/vault.js', '../privacy/model-loader.js', '../privacy/vision-runner.js', '../privacy/redactor.js', '../privacy/gate.js');
    } catch (e2) {
      console.error('Failed to import background scripts:', e2);
    }
  }
}

const api = globalThis.browser ?? globalThis.chrome;
const sessionStore = api.storage.session ?? api.storage.local;
const MAX_STEPS = 8;
const WHITELIST_ACTIONS = ['click', 'type', 'select', 'scroll', 'done'];

const DEFAULT_PASSPHRASE = 'veil-local-key-passphrase';
const DEFAULT_VAULT = globalThis.VeilVault?.DEFAULT_PROFILES || {
  schema_version: '1.0',
  active_profile: 'default',
  profiles: {
    default: {
      FULL_NAME: 'Asha Verma',
      FIRST_NAME: 'Asha',
      LAST_NAME: 'Verma',
      DOB: '1995-08-15',
      GENDER: 'Female',
      EMAIL: 'asha@example.com',
      MOBILE: '9876543210',
      ADDRESS_LINE1: 'Flat 402, Shanti Niketan',
      ADDRESS_LINE2: 'MG Road',
      CITY: 'Bangalore',
      DISTRICT: 'Bangalore Urban',
      STATE: 'Karnataka',
      PIN: '560001',
      FATHER_NAME: 'Ramesh Verma',
      MOTHER_NAME: 'Sunita Verma',
      CATEGORY: 'General',
      AADHAAR: '367598346012',
      PAN: 'ABCDE1234F',
      IFSC: 'SBIN0001234',
      ACCOUNT_NO: '12345678901'
    }
  }
};

// In-memory cache for decrypted vault, current tokenizer, and server inspection view
let memoryVault = null;
let currentTokenizer = null;
let lastServerInspectionView = null;

// Initialize WebCrypto encrypted vault on install
api.runtime.onInstalled.addListener(async () => {
  const existing = await api.storage.local.get('vault_encrypted');
  if (!existing?.vault_encrypted && globalThis.VeilVault?.encryptVault) {
    const encrypted = await globalThis.VeilVault.encryptVault(DEFAULT_VAULT, DEFAULT_PASSPHRASE);
    await api.storage.local.set({
      vault_encrypted: encrypted,
      approvedDomains: ['localhost', '127.0.0.1'],
      agentMode: 'Balanced', // Default mode
      showLast4: false
    });
    await sessionStore.set({ vault_passphrase: DEFAULT_PASSPHRASE });
  }
});

// Decrypt vault in memory / session storage only (never sent to content scripts or disk)
async function getDecryptedVault() {
  if (memoryVault) return memoryVault;

  const { vault_encrypted } = await api.storage.local.get('vault_encrypted');
  if (!vault_encrypted) return DEFAULT_VAULT;

  const { vault_passphrase } = await sessionStore.get('vault_passphrase');
  const pass = vault_passphrase || DEFAULT_PASSPHRASE;

  if (globalThis.VeilVault?.decryptVault) {
    try {
      memoryVault = await globalThis.VeilVault.decryptVault(vault_encrypted, pass);
      return memoryVault;
    } catch (e) {
      console.error('Vault decryption error:', e);
      return DEFAULT_VAULT;
    }
  }
  return DEFAULT_VAULT;
}

async function getStoredData() {
  const data = await sessionStore.get(['agent_state', 'agent_logs']);
  return {
    state: data.agent_state || {
      goal: '',
      step: 0,
      history: [],
      status: 'idle',
      pendingAction: null,
      error: null,
      tabId: null
    },
    logs: data.agent_logs || []
  };
}

async function updateState(partial) {
  const { state } = await getStoredData();
  const next = { ...state, ...partial };
  await sessionStore.set({ agent_state: next });
  api.runtime.sendMessage({ type: 'STATE_CHANGED', state: next }).catch(() => {});
  return next;
}

async function appendLog(line) {
  const { logs } = await getStoredData();
  logs.push(line);
  await sessionStore.set({ agent_logs: logs });
  api.runtime.sendMessage({ type: 'LOG', line }).catch(() => {});
}

async function clearLogs() {
  await sessionStore.set({ agent_logs: [] });
  api.runtime.sendMessage({ type: 'CLEAR_LOGS' }).catch(() => {});
}

async function ensureContentScript(tabId) {
  try {
    const ping = await api.tabs.sendMessage(tabId, { type: 'PING' });
    if (ping?.ok) return true;
  } catch (_) {}

  try {
    await api.scripting.executeScript({
      target: { tabId },
      files: ['workers/pii.js', 'privacy/injection-shield.js', 'content/dom-capture.js', 'content/executor.js']
    });
    await new Promise((r) => setTimeout(r, 80));
    return true;
  } catch (err) {
    throw new Error(`no content script available on active tab (${err.message})`);
  }
}

// Invariant 4, Task 1 & Task 2: Placeholder and Token Resolution
async function validateAndResolveValue(value, tabUrl) {
  if (value === null || value === undefined) return value;
  if (typeof value !== 'string') {
    throw new Error('Action rejected: value must be a string');
  }

  // Task 2: Refuse to fill identity fields on unencrypted http:// pages
  const isPlainHttp = tabUrl && tabUrl.startsWith('http:') &&
    !tabUrl.startsWith('http://localhost') &&
    !tabUrl.startsWith('http://127.0.0.1');

  const vault = await getDecryptedVault();

  // 1. Check if value is a session token issued by the Tokenizer
  if (currentTokenizer && currentTokenizer.isSessionToken(value)) {
    if (isPlainHttp) {
      throw new Error('Action rejected: refusing to fill identity fields on unencrypted http:// page');
    }
    const resolved = currentTokenizer.resolve(value);
    if (resolved !== null) return resolved;
  }

  // 2. Check if value matches exact vault keys {{KEY}}
  const placeholderRegex = /\{\{([A-Z0-9_]+)\}\}/g;
  let match;
  let hasPlaceholder = false;

  while ((match = placeholderRegex.exec(value)) !== null) {
    hasPlaceholder = true;
    const key = match[1];
    const val = getVaultValue(vault, key);
    if (!val) {
      throw new Error(`Action rejected: unknown vault placeholder {{${key}}}`);
    }
  }

  if (hasPlaceholder) {
    if (isPlainHttp) {
      throw new Error('Action rejected: refusing to fill identity fields on unencrypted http:// page');
    }
    return value.replace(placeholderRegex, (_, k) => getVaultValue(vault, k));
  }

  // 3. Reject unknown tokens or tokens from page content
  if (/^\[[A-Z0-9_]+\]$/.test(value.trim())) {
    throw new Error(`Action rejected: token ${value} was not issued in this session`);
  }

  // Plain text must not exceed 500 chars (for free-text drafts)
  if (value.length > 500) {
    throw new Error('Action rejected: typed plain text exceeds 500 characters');
  }

  return value;
}

function getVaultValue(vault, key) {
  if (!vault || !key) return '';
  const normKey = key.toUpperCase().trim();
  const profile = globalThis.VeilVault?.getProfile ? globalThis.VeilVault.getProfile(vault) : vault;

  // Direct match
  if (profile[normKey] !== undefined) return profile[normKey];

  // Common aliases
  if (normKey === 'NAME' && profile.FULL_NAME) return profile.FULL_NAME;
  if (normKey === 'FULL_NAME' && profile.NAME) return profile.NAME;
  if (normKey === 'PHONE' && profile.MOBILE) return profile.MOBILE;
  if (normKey === 'MOBILE' && profile.PHONE) return profile.PHONE;

  // Composed values (DOB formats, split fields, name parts)
  if (globalThis.VeilVault?.compose) {
    const comp = globalThis.VeilVault.compose(normKey, profile);
    if (comp) return comp;
  }

  return '';
}

// Task 7: Answer path token resolution for DISPLAY ONLY (never innerHTML, never written to page, never sent back)
function resolveDisplayTokens(text, tokenizer) {
  if (typeof text !== 'string') return '';
  return text.replace(/\[([A-Z0-9_]+)\]/g, (match) => {
    if (tokenizer && typeof tokenizer.resolve === 'function') {
      const realVal = tokenizer.resolve(match);
      if (realVal !== null && realVal !== undefined) {
        return realVal;
      }
    }
    return '[unknown]';
  });
}

function isSubmitAction(action, nodes = []) {
  if (action.action !== 'click') return false;
  const node = nodes.find((n) => n.id === action.target_id);
  const label = (node?.label || '').toLowerCase();
  const reason = (action.reason || '').toLowerCase();
  const type = (node?.type || '').toLowerCase();
  const tag = (node?.tag || '').toLowerCase();

  return (
    type === 'submit' ||
    ((tag === 'button' || tag === 'input') && /submit|apply|register|complete|proceed/i.test(label || reason))
  );
}

function isRiskyClick(action, nodes = []) {
  if (action.action !== 'click') return false;
  const node = nodes.find((n) => n.id === action.target_id);
  const label = (node?.label || '').toLowerCase();
  const reason = (action.reason || '').toLowerCase();
  const type = (node?.type || '').toLowerCase();
  const tag = (node?.tag || '').toLowerCase();

  const pattern = /submit|pay|buy|delete|confirm|send/;
  if (type === 'submit' || tag === 'button') {
    return pattern.test(label) || pattern.test(reason) || type === 'submit';
  }
  return pattern.test(label) || pattern.test(reason);
}

// Execute single validated step or queue for approval
async function executeStep(tabId, action, rawAction, goal, step, history, nodes, options = {}) {
  // Check for repeated actions (Task 7)
  if (history.length >= 2) {
    const prev1 = history[history.length - 1];
    const prev2 = history[history.length - 2];
    if (
      prev1.action === rawAction.action &&
      prev1.target_id === rawAction.target_id &&
      prev1.value === rawAction.value &&
      prev2.action === rawAction.action &&
      prev2.target_id === rawAction.target_id &&
      prev2.value === rawAction.value
    ) {
      await appendLog(`Stopped: detected repeated action twice (${rawAction.action} on ${rawAction.target_id ?? 'page'}).`);
      await updateState({ status: 'stopped' });
      return { stopped: true };
    }
  }

  // Visual-only node validation & coordinate click enforcement (Invariant 16 & Task 4)
  const targetNode = nodes.find((n) => n.id === action.target_id);
  const isVisualOnly = (action.target_id && action.target_id.startsWith('vo')) || targetNode?.role === 'visual_only';

  if (isVisualOnly) {
    if (action.action === 'type') {
      const err = 'Action rejected: typing into visual_only nodes is strictly forbidden (Invariant 16)';
      await appendLog(err);
      await updateState({ status: 'error', error: err });
      return { error: err };
    }

    if (action.action !== 'click') {
      const err = `Action rejected: visual_only nodes may only be targeted by coordinate click, received '${action.action}'`;
      await appendLog(err);
      await updateState({ status: 'error', error: err });
      return { error: err };
    }

    if (globalThis.VeilVisionRunner?.validateVisualClick) {
      try {
        const valRes = globalThis.VeilVisionRunner.validateVisualClick(
          action,
          targetNode,
          options.viewport || [1280, 800],
          options.redactions || []
        );
        action.coords = valRes.coords;
        rawAction.coords = valRes.coords;
      } catch (valErr) {
        await appendLog(valErr.message);
        await updateState({ status: 'error', error: valErr.message });
        return { error: valErr.message };
      }
    }

    // Invariant 16: Asks the user to Approve (autoApprove stays off)
    await updateState({
      status: 'waiting_approval',
      pendingAction: action,
      rawAction,
      goal,
      step,
      history,
      tabId
    });
    await appendLog(`Waiting for approval: coordinate click on visual_only node ${action.target_id} at (${action.coords[0]}, ${action.coords[1]})`);
    return { waitingApproval: true };
  }

  // Risky click approval check (Task 4)
  if (isRiskyClick(rawAction, nodes)) {
    const { autoApprove = false } = await api.storage.local.get('autoApprove');
    if (!autoApprove) {
      await updateState({
        status: 'waiting_approval',
        pendingAction: action,
        rawAction,
        goal,
        step,
        history,
        tabId
      });
      await appendLog(`Waiting for approval: ${action.action} ${action.target_id ?? ''} (${rawAction.reason || 'risky action'})`);
      return { waitingApproval: true };
    }
    await appendLog(`Auto-approved risky click: ${action.target_id}`);
  }

  // Phase 8: Review-Before-Submit Table (Task 7)
  if (isSubmitAction(rawAction, nodes) && !options.reviewApproved) {
    const { state: curState } = await getStoredData();
    const filled = curState.filledFields || [];
    const reviewTable = filled.map((f) => ({
      nodeId: f.nodeId,
      label: f.label || f.nodeId,
      value: f.value,
      masked: globalThis.VeilVault?.maskValue ? globalThis.VeilVault.maskValue(f.value, (f.key || '').toLowerCase(), true) : f.value,
      source: f.source || 'Vault',
      sensitivity: globalThis.VeilVault?.getSensitivity ? globalThis.VeilVault.getSensitivity(f.key) : 'low'
    }));

    await updateState({
      status: 'waiting_review',
      pendingAction: action,
      rawAction,
      goal,
      step,
      history,
      tabId,
      reviewTable,
      approvalReason: 'Review form values before submission'
    });
    await appendLog(`Approval required: Review-Before-Submit table generated (${reviewTable.length} fields).`);
    return { waitingApproval: true };
  }

  // Target frame handling (Task 1 & 2)
  let targetFrameId = 0;
  let localTargetId = action.target_id;
  if (action.target_id) {
    const m = action.target_id.match(/^f(\d+):(.*)$/);
    if (m) {
      targetFrameId = parseInt(m[1], 10);
      localTargetId = m[2];
    }
  }

  // Cross-origin iframe vault filling protection (Task 2)
  const targetFrameOrigin = targetNode?.frameOrigin || frameOriginsMap.get(targetFrameId);
  const topOrigin = options.topOrigin;
  const isCrossOriginFrame = targetFrameOrigin && topOrigin && targetFrameOrigin !== topOrigin;

  if (isCrossOriginFrame && action.action === 'type' && action.value) {
    const isVaultValue = (rawAction.value && rawAction.value.includes('[')) ||
                         (rawAction.value && rawAction.value.includes('{{')) ||
                         action.value !== rawAction.value;
    if (isVaultValue) {
      const { approvedOrigins = [] } = await api.storage.local.get('approvedOrigins');
      if (!approvedOrigins.includes(targetFrameOrigin)) {
        await updateState({
          status: 'waiting_approval',
          pendingAction: action,
          rawAction,
          goal,
          step,
          history,
          tabId,
          approvalReason: `Cross-origin vault fill blocked for frame origin "${targetFrameOrigin}". User approval required.`
        });
        await appendLog(`Approval required: Filling vault credentials into cross-origin frame (${targetFrameOrigin}) is blocked by default.`);
        return { waitingApproval: true };
      }
    }
  }

  // Content script receives ONLY the single action with its specific value (never the vault!)
  const actionForContent = { ...action, target_id: localTargetId };
  const msgOpts = targetFrameId > 0 ? { frameId: targetFrameId } : undefined;
  let result;
  try {
    result = await api.tabs.sendMessage(tabId, { type: 'EXECUTE', action: actionForContent }, msgOpts);
  } catch (execErr) {
    result = await api.tabs.sendMessage(tabId, { type: 'EXECUTE', action: actionForContent });
  }

  // Phase 8: Stop conditions handling (Task 4)
  if (result?.stopCondition) {
    await updateState({
      status: 'waiting_user',
      stopCondition: result.conditionType,
      stopMessage: result.message,
      pendingAction: action,
      rawAction,
      goal,
      step,
      history,
      tabId
    });
    await appendLog(`Stop condition encountered: ${result.message}`);
    return { waitingApproval: true, stopped: true };
  }

  // Phase 8: Consent checkbox safety (Task 3)
  if (result?.isConsent || (result?.requiresApproval && !options.consentApproved)) {
    await updateState({
      status: 'waiting_approval',
      pendingAction: action,
      rawAction,
      goal,
      step,
      history,
      tabId,
      approvalReason: result.error || 'Consent/declaration checkboxes require user approval'
    });
    await appendLog(`Approval required: ${result.error || 'Consent checkbox requires approval'}`);
    return { waitingApproval: true };
  }

  // Dynamic page stale ID handling - recapture without guessing (Task 4)
  if (result?.stale) {
    await appendLog(`Stale element detected for ${action.target_id}: dynamic DOM changed. Recapturing without guessing.`);
    return { ok: false, stale: true };
  }

  if (!result?.ok) {
    const err = result?.error ?? 'unknown execution error';
    await appendLog('Execution failed: ' + err);
    await updateState({ status: 'error', error: err });
    return { error: err };
  }

  // Phase 8: Accumulate filled field for Review-Before-Submit table
  if (action.action === 'type' || action.action === 'select') {
    const { state: curState } = await getStoredData();
    const filled = curState.filledFields || [];
    const keyMatch = (rawAction.value || '').match(/\{\{([A-Z0-9_]+)\}\}/);
    const vaultKey = keyMatch ? keyMatch[1] : (action.action === 'select' ? 'SELECT' : 'DRAFTED');
    filled.push({
      nodeId: action.target_id,
      label: targetNode?.label || targetNode?.text || action.target_id,
      value: action.value,
      key: vaultKey,
      source: keyMatch ? `Vault: ${vaultKey}` : (action.action === 'select' ? 'Selection' : 'Drafted'),
      sensitivity: globalThis.VeilVault?.getSensitivity ? globalThis.VeilVault.getSensitivity(vaultKey) : 'low'
    });
    await updateState({ filledFields: filled });
  }

  // Append raw action (with placeholder/tokens, NOT resolved PII) to history
  history.push(rawAction);
  await updateState({ step: step + 1, history });
  return { ok: true };
}

// Main execution loop
async function runAgent(goal) {
  await clearLogs();
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    await appendLog('Error: no active tab found.');
    await updateState({ status: 'error', error: 'No active tab found' });
    return;
  }

  // Task 2: Check domain approval
  let domain = 'local';
  try {
    domain = new URL(tab.url).hostname || 'local';
  } catch (_) {}

  const { approvedDomains = ['localhost', '127.0.0.1'] } = await api.storage.local.get('approvedDomains');
  if (domain !== 'local' && !approvedDomains.includes(domain)) {
    await updateState({
      status: 'waiting_approval',
      pendingDomainApproval: domain,
      goal,
      tabId: tab.id
    });
    await appendLog(`Domain approval required: ${domain}`);
    return;
  }

  // Initialize session tokenizer
  const { showLast4 = false } = await api.storage.local.get('showLast4');
  if (globalThis.VeilVault?.createSessionTokenizer) {
    currentTokenizer = globalThis.VeilVault.createSessionTokenizer({ showLast4 });
    // Issue session tokens for vault entries
    const vault = await getDecryptedVault();
    for (const [k, v] of Object.entries(vault)) {
      currentTokenizer.tokenize(v, k);
    }
  }

  const history = [];
  await updateState({
    goal,
    step: 1,
    history,
    status: 'running',
    error: null,
    pendingAction: null,
    tabId: tab.id,
    filledFields: []
  });

  await runLoopFrom(tab.id, goal, 1, history, tab.url);
}

// Frame origin map for security and vault protection (Task 1 & 2)
const frameOriginsMap = new Map();

async function captureAllFrames(tabId, options = {}) {
  frameOriginsMap.clear();
  let frameSnapshots = [];

  // Try scripting executeScript in all frames (Task 1)
  if (api.scripting?.executeScript) {
    try {
      const results = await api.scripting.executeScript({
        target: { tabId, allFrames: true },
        func: (opts) => {
          return globalThis.__veil?.capture ? globalThis.__veil.capture(opts) : null;
        },
        args: [options]
      });
      frameSnapshots = (results || [])
        .filter((r) => r && r.result)
        .map((r) => ({ frameId: r.frameId ?? 0, dom: r.result }));
    } catch (_) {}
  }

  // Fallback to tabs.sendMessage if executeScript was empty or unavailable
  if (frameSnapshots.length === 0) {
    const single = await api.tabs.sendMessage(tabId, { type: 'CAPTURE', mode: options.mode });
    if (single?.ok && single?.dom) {
      frameSnapshots = [{ frameId: 0, dom: single.dom }];
    }
  }

  if (frameSnapshots.length === 0) {
    throw new Error('no content script responding on active tab');
  }

  // Find top frame (frameId 0 or isTop)
  const topSnapshot = frameSnapshots.find((f) => f.frameId === 0 || f.dom?.isTop) || frameSnapshots[0];
  const topOrigin = topSnapshot.dom.origin || (new URL(topSnapshot.dom.url)).origin;
  frameOriginsMap.set(topSnapshot.frameId, topOrigin);

  const allNodes = [];
  const topViewport = topSnapshot.dom.viewport || [1280, 800];
  let totalSuspectText = 0;

  for (const f of frameSnapshots) {
    if (f.dom?.suspectTextCount) totalSuspectText += f.dom.suspectTextCount;
  }

  // Frame 0 nodes (qualified with f0: or frameId)
  for (const node of (topSnapshot.dom.nodes || [])) {
    const qualifiedId = node.id.startsWith('f') ? node.id : `f${topSnapshot.frameId}:${node.id}`;
    allNodes.push({
      ...node,
      id: qualifiedId,
      frameId: topSnapshot.frameId,
      frameOrigin: topOrigin
    });
  }

  // Subframes handling (Task 1 & 2) - max depth 3, cap 400 nodes
  const childIframes = topSnapshot.dom.childFrames || [];
  const subframes = frameSnapshots.filter((f) => f !== topSnapshot);

  for (let i = 0; i < subframes.length; i++) {
    const sub = subframes[i];
    const subOrigin = sub.dom.origin || 'about:blank';
    frameOriginsMap.set(sub.frameId, subOrigin);

    // Compute frame offset from top frame's childIframes if available
    let frameOffset = [0, 0];
    if (i < childIframes.length && childIframes[i].bbox) {
      frameOffset = [childIframes[i].bbox[0], childIframes[i].bbox[1]];
    }

    for (const node of (sub.dom.nodes || [])) {
      const qualifiedId = node.id.startsWith('f') ? node.id : `f${sub.frameId}:${node.id}`;
      const adjustedBox = [
        node.bbox[0] + frameOffset[0],
        node.bbox[1] + frameOffset[1],
        node.bbox[2],
        node.bbox[3]
      ];
      allNodes.push({
        ...node,
        id: qualifiedId,
        frameId: sub.frameId,
        frameOrigin: subOrigin,
        bbox: adjustedBox
      });
    }
  }

  // Viewport-first sorting across all nodes (Task 1 & 5)
  const vw = topViewport[0];
  const vh = topViewport[1];
  allNodes.sort((a, b) => {
    const aInView = a.bbox[0] >= 0 && a.bbox[1] >= 0 && a.bbox[0] < vw && a.bbox[1] < vh;
    const bInView = b.bbox[0] >= 0 && b.bbox[1] >= 0 && b.bbox[0] < vw && b.bbox[1] < vh;
    if (aInView && !bInView) return -1;
    if (!aInView && bInView) return 1;
    return 0;
  });

  // Cap nodes (Open mode: 800, Balanced/Strict: 400)
  const maxNodes = options.mode === 'Open' ? 800 : 400;
  const cappedNodes = allNodes.slice(0, maxNodes);

  return {
    ok: true,
    dom: {
      url: topSnapshot.dom.url,
      title: topSnapshot.dom.title,
      viewport: topViewport,
      scrollY: topSnapshot.dom.scrollY,
      nodes: cappedNodes,
      suspectTextCount: totalSuspectText
    },
    topOrigin,
    frameOrigins: frameOriginsMap
  };
}

async function runLoopFrom(tabId, goal, startStep, history, tabUrl) {
  if (!tabUrl) {
    try {
      const tab = await api.tabs.get(tabId);
      tabUrl = tab?.url || '';
    } catch (_) {}
  }

  for (let step = startStep; step <= MAX_STEPS; step++) {
    // Check if stopped mid-run
    const { state } = await getStoredData();
    if (state.status === 'stopped') {
      await appendLog('Stopped.');
      return;
    }

    // Ensure content script is present
    try {
      await ensureContentScript(tabId);
    } catch (e) {
      await appendLog('Error: ' + e.message);
      await updateState({ status: 'error', error: e.message });
      return;
    }

    // Read operating mode: Strict vs. Balanced vs. Open (Only user can change via popup)
    const { agentMode = 'Balanced' } = await api.storage.local.get('agentMode');
    let screenshotData = null;
    let redactionManifest = [];
    let effectiveMode = agentMode;
    let redactResult = null;

    // Capture sanitized DOM across all frames with operating mode limits
    let cap;
    try {
      cap = await captureAllFrames(tabId, { mode: agentMode });
      if (!cap?.ok || !cap?.dom) throw new Error('invalid capture response');
    } catch (e) {
      const msg = 'Error: no content script responding on active tab (' + e.message + ')';
      await appendLog(msg);
      await updateState({ status: 'error', error: msg });
      return;
    }

    if ((agentMode === 'Balanced' || agentMode === 'Open') && globalThis.VeilRedactor?.captureAndRedact) {
      redactResult = await globalThis.VeilRedactor.captureAndRedact(tabId, cap.dom, { mode: agentMode });
      if (redactResult.degraded) {
        effectiveMode = 'Strict';
        screenshotData = null;
        redactionManifest = [];
        await appendLog(`Redaction degraded to Strict mode: ${redactResult.reason}`);
      } else {
        screenshotData = redactResult.image;
        redactionManifest = redactResult.manifest;
        effectiveMode = agentMode;

        // UI Context Detection (Task 3, 4, Invariants 14-16)
        // Runs ONLY on already-redacted image canvas
        if (globalThis.VeilVisionRunner?.runUIContextDetection && redactResult.canvasCtx) {
          try {
            const uiResult = await globalThis.VeilVisionRunner.runUIContextDetection(
              redactResult.canvasCtx,
              cap.dom.nodes,
              {
                timeoutMs: 1500,
                viewport: cap.dom.viewport,
                redactions: redactionManifest
              }
            );
            cap.dom.nodes = uiResult.fusedNodes || cap.dom.nodes;
            if (uiResult.visualOnlyNodes?.length > 0) {
              await appendLog(`Fusion added ${uiResult.visualOnlyNodes.length} visual_only node(s) (${uiResult.visualOnlyNodes.map((v) => v.id).join(', ')}). Context accuracy: ${uiResult.contextAccuracy}`);
            }
          } catch (uiErr) {
            // Invariant 15: Failure falls back cleanly to DOM only
            await appendLog(`UI detector degraded to DOM-only: ${uiErr.message}`);
          }
        }

        // Cache view in memory for user inspection view ("What the server sees")
        lastServerInspectionView = {
          time: new Date().toISOString(),
          mode: agentMode,
          originalImage: redactResult.original,
          redactedImage: redactResult.image,
          dom: cap.dom,
          manifest: redactResult.manifest,
          clearedMedia: redactResult.clearedMediaIds || [],
          vision: redactResult.vision || null
        };
      }
    } else {
      effectiveMode = 'Strict';
      screenshotData = null;
      redactionManifest = [];
    }

    // Phase 8: Layered Field Matching (Local First, VLM only for ambiguity)
    let localAction = null;
    const doneTargets = new Set();
    for (const h of history) {
      if (h.target_id) doneTargets.add(h.target_id);
    }

    if (globalThis.FieldMatcher?.matchField) {
      for (const node of cap.dom.nodes) {
        if (
          (node.tag === 'input' || node.tag === 'select' || node.tag === 'textarea') &&
          !node.sensitive &&
          !doneTargets.has(node.id)
        ) {
          const itype = (node.type || '').toLowerCase();
          if (itype === 'submit' || itype === 'button' || itype === 'hidden') continue;

          const match = globalThis.FieldMatcher.matchField(node);
          if (match && match.isConsent) {
            // Consent checkbox safety invariant: NEVER auto-tick!
            await updateState({
              status: 'waiting_approval',
              pendingAction: { action: 'click', target_id: node.id },
              rawAction: { type: 'action', action: 'click', target_id: node.id, reason: 'Consent/declaration approval' },
              approvalReason: `Consent required: "${node.label || 'terms and conditions'}". Approve checking this declaration?`
            });
            await appendLog(`Consent required: "${node.label || 'terms'}". Awaiting user approval.`);
            return;
          }

          if (match && match.vaultKey && match.confidence >= 0.70) {
            const vaultKey = match.vaultKey;
            const val = getVaultValue(vault, vaultKey);
            if (val) {
              // Task 5: Data minimization check
              const isLowStakes = /newsletter|subscribe|contact|feedback|survey/i.test(cap.dom.title || '');
              if (isLowStakes && globalThis.VeilVault?.isHighSensitivity(vaultKey)) {
                await appendLog(`Data Minimization: Skipped high-sensitivity field "${vaultKey}" on low-stakes page.`);
                doneTargets.add(node.id);
                continue;
              }

              localAction = {
                type: 'action',
                action: node.tag === 'select' ? 'select' : 'type',
                target_id: node.id,
                value: `{{${vaultKey}}}`,
                reason: match.reason
              };
              break;
            }
          }
        }
      }
    }

    if (localAction) {
      const rawAction = { ...localAction };
      const executableAction = { ...localAction };
      try {
        executableAction.value = await validateAndResolveValue(executableAction.value, tabUrl);
      } catch (err) {
        await appendLog(err.message);
        await updateState({ status: 'error', error: err.message });
        return;
      }

      await appendLog(`step ${step} [local matcher]: ${executableAction.action} ${executableAction.target_id} - ${executableAction.reason}`);
      const stepResult = await executeStep(
        tabId,
        executableAction,
        rawAction,
        goal,
        step,
        history,
        cap.dom.nodes,
        { viewport: cap.dom.viewport, redactions: redactionManifest, topOrigin: cap.topOrigin }
      );
      if (stepResult.stopped || stepResult.error) return;
      if (stepResult.waitingApproval) return;
      if (stepResult.stale) continue;
      continue;
    }

    const payload = {
      goal,
      step,
      dom: cap.dom,
      screenshot: screenshotData,
      redactions: redactionManifest,
      cleared_media: redactResult?.clearedMediaIds || [],
      vision: redactResult?.vision || null,
      history,
      mode: effectiveMode,
      suspect_text_count: cap.dom.suspectTextCount || 0
    };

    let serverResponse;
    try {
      serverResponse = await globalThis.sendSanitized('/plan', payload, (receipt) => {
        appendLog(`gate sent ${receipt.bytes} bytes (${effectiveMode} mode) [hash: ${receipt.hash.slice(0, 10)}...]`);
      });
    } catch (e) {
      const errMsg = e.message.includes('Failed to fetch')
        ? 'server down (connection failed)'
        : e.message;
      await appendLog('GATE BLOCKED / FAILED: ' + errMsg);
      await updateState({ status: 'error', error: errMsg });
      return;
    }

    const latency = serverResponse._latencyMs || 0;
    const stepTelemetry = {
      latency,
      bytes: serverResponse._requestBytes || 0,
      redactions: redactionManifest.length,
      mode: effectiveMode,
      step
    };
    await sessionStore.set({ last_step_telemetry: stepTelemetry });
    api.runtime.sendMessage({ type: 'TELEMETRY_UPDATED', telemetry: stepTelemetry }).catch(() => {});

    // Normalize response type
    let respType = serverResponse.type;
    if (!respType && serverResponse.action) {
      if (serverResponse.action === 'done') respType = 'done';
      else if (serverResponse.action === 'fail') respType = 'fail';
      else respType = 'action';
    }

    // Task 7: Answer Response
    if (respType === 'answer') {
      const rawText = serverResponse.text || '';
      // Resolve session tokens to real values for DISPLAY ONLY (never innerHTML, never written to page, never sent back)
      const resolvedDisplayAnswer = resolveDisplayTokens(rawText, currentTokenizer);
      await appendLog(`step ${step} [${latency}ms]: Answer received: ${resolvedDisplayAnswer}`);
      await updateState({
        status: 'answered',
        answer: resolvedDisplayAnswer,
        rawAnswer: rawText,
        step
      });
      return;
    }

    // Done Response
    if (respType === 'done') {
      const doneReason = serverResponse.reason || 'task completed';
      await appendLog(`step ${step} [${latency}ms]: Done: ${doneReason}`);
      await updateState({ status: 'done', step, reason: doneReason });
      return;
    }

    // Fail Response
    if (respType === 'fail') {
      const failReason = serverResponse.reason || 'task failed';
      await appendLog(`step ${step} [${latency}ms]: Server returned fail: ${failReason}`);
      await updateState({ status: 'error', error: failReason, step });
      return;
    }

    // Ask User Response
    if (respType === 'ask_user') {
      const question = serverResponse.question || 'Please confirm action.';
      await appendLog(`step ${step} [${latency}ms]: Agent asks user: ${question}`);
      await updateState({
        status: 'waiting_user_input',
        question,
        reason: serverResponse.reason,
        step
      });
      return;
    }

    // Action Response
    if (respType === 'action') {
      const serverAction = serverResponse;
      if (!serverAction || !WHITELIST_ACTIONS.includes(serverAction.action)) {
        const err = `Action rejected: untrusted or unsupported action "${serverAction?.action}"`;
        await appendLog(err);
        await updateState({ status: 'error', error: err });
        return;
      }

      await appendLog(`step ${step} [${latency}ms]: ${serverAction.action} ${serverAction.target_id ?? ''} - ${serverAction.reason ?? ''}`);

      // Keep raw action for stateless server history
      const rawAction = { ...serverAction };

      // Resolve vault placeholders locally (Invariant 4)
      const executableAction = { ...serverAction };
      if (executableAction.action === 'type') {
        try {
          executableAction.value = await validateAndResolveValue(executableAction.value, tabUrl);
        } catch (err) {
          await appendLog(err.message);
          await updateState({ status: 'error', error: err.message });
          return;
        }
      }

      const stepResult = await executeStep(
        tabId,
        executableAction,
        rawAction,
        goal,
        step,
        history,
        cap.dom.nodes,
        { viewport: cap.dom.viewport, redactions: redactionManifest, topOrigin: cap.topOrigin }
      );
      if (stepResult.stopped || stepResult.error) return;
      if (stepResult.waitingApproval) {
        return;
      }
      if (stepResult.stale) {
        // Dynamic re-render: DOM will be refreshed on next step without guessing (Task 4)
        continue;
      }
    }
  }

  await appendLog('Stopped: step limit of 8 reached.');
  await updateState({ status: 'stopped' });
}

// User action approvals and controls
api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'RUN') {
    runAgent(msg.goal).catch((e) => appendLog('Error: ' + e.message));
    sendResponse({ ok: true });
    return false;
  }

  if (msg?.type === 'STOP') {
    updateState({ status: 'stopped', pendingAction: null }).then(() => {
      appendLog('Run stopped by user.');
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg?.type === 'APPROVE_DOMAIN') {
    (async () => {
      const { state } = await getStoredData();
      if (!state.pendingDomainApproval) {
        sendResponse({ ok: false, error: 'no pending domain approval' });
        return;
      }
      const domain = state.pendingDomainApproval;
      const { approvedDomains = ['localhost', '127.0.0.1'] } = await api.storage.local.get('approvedDomains');
      if (!approvedDomains.includes(domain)) {
        approvedDomains.push(domain);
        await api.storage.local.set({ approvedDomains });
      }
      await appendLog(`Domain approved: ${domain}`);
      await updateState({ pendingDomainApproval: null, status: 'running' });
      sendResponse({ ok: true });
      runAgent(state.goal).catch((e) => appendLog('Error: ' + e.message));
    })();
    return true;
  }

  if (msg?.type === 'APPROVE_ACTION') {
    (async () => {
      const { state } = await getStoredData();
      if (state.status !== 'waiting_approval' || !state.pendingAction) {
        sendResponse({ ok: false, error: 'no pending approval' });
        return;
      }

      await appendLog(`Approved by user: ${state.pendingAction.action} on ${state.pendingAction.target_id}`);
      await updateState({ status: 'running' });

      // Execute approved action with target frame routing
      let targetFrameId = 0;
      let localTargetId = state.pendingAction.target_id;
      if (state.pendingAction.target_id) {
        const m = state.pendingAction.target_id.match(/^f(\d+):(.*)$/);
        if (m) {
          targetFrameId = parseInt(m[1], 10);
          localTargetId = m[2];
        }
      }
      const actionForContent = { ...state.pendingAction, target_id: localTargetId };
      const msgOpts = targetFrameId > 0 ? { frameId: targetFrameId } : undefined;
      let result;
      try {
        result = await api.tabs.sendMessage(state.tabId, {
          type: 'EXECUTE',
          action: actionForContent
        }, msgOpts);
      } catch (_) {
        result = await api.tabs.sendMessage(state.tabId, {
          type: 'EXECUTE',
          action: actionForContent
        });
      }

      if (!result?.ok) {
        const err = result?.error ?? 'execution error';
        await appendLog('Execution failed: ' + err);
        await updateState({ status: 'error', error: err });
        sendResponse({ ok: false, error: err });
        return;
      }

      const history = [...state.history, state.rawAction];
      const nextStep = state.step + 1;
      await updateState({ step: nextStep, history, pendingAction: null });
      sendResponse({ ok: true });

      // Resume loop
      runLoopFrom(state.tabId, state.goal, nextStep, history, '').catch((e) =>
        appendLog('Error resuming: ' + e.message)
      );
    })();
    return true;
  }

  if (msg?.type === 'SKIP_ACTION') {
    (async () => {
      const { state } = await getStoredData();
      if (state.status !== 'waiting_approval' || !state.pendingAction) {
        sendResponse({ ok: false, error: 'no pending approval' });
        return;
      }

      await appendLog(`Skipped by user: ${state.pendingAction.action} on ${state.pendingAction.target_id}`);
      const history = [...state.history, state.rawAction];
      const nextStep = state.step + 1;
      await updateState({ status: 'running', step: nextStep, history, pendingAction: null });
      sendResponse({ ok: true });

      runLoopFrom(state.tabId, state.goal, nextStep, history, '').catch((e) =>
        appendLog('Error resuming: ' + e.message)
      );
    })();
    return true;
  }

  if (msg?.type === 'GET_SERVER_VIEW') {
    sendResponse({ ok: true, view: lastServerInspectionView });
    return false;
  }

  if (msg?.type === 'CLEAR_SERVER_VIEW') {
    if (lastServerInspectionView) {
      lastServerInspectionView.originalImage = null;
      lastServerInspectionView = null;
    }
    sendResponse({ ok: true });
    return false;
  }

  // Phase 8: Message listeners for Review-Before-Submit, Manual Resume, and Clarification
  if (msg?.type === 'APPROVE_REVIEW') {
    (async () => {
      const { state } = await getStoredData();
      if (!state.pendingAction) {
        sendResponse({ ok: false, error: 'no pending submit action' });
        return;
      }
      await appendLog('Review-before-submit approved by user.');
      await updateState({ status: 'running' });

      // Execute submit action with reviewApproved: true
      const stepResult = await executeStep(
        state.tabId,
        state.pendingAction,
        state.rawAction,
        state.goal,
        state.step,
        state.history,
        [],
        { reviewApproved: true }
      );
      if (stepResult.stopped || stepResult.error) {
        sendResponse({ ok: false });
        return;
      }
      const history = [...state.history, state.rawAction];
      const nextStep = state.step + 1;
      await updateState({ step: nextStep, history, pendingAction: null });
      sendResponse({ ok: true });
      runLoopFrom(state.tabId, state.goal, nextStep, history, '').catch((e) =>
        appendLog('Error resuming: ' + e.message)
      );
    })();
    return true;
  }

  if (msg?.type === 'RESUME_TASK') {
    (async () => {
      const { state } = await getStoredData();
      await appendLog('Resumed after manual user action.');
      await updateState({ status: 'running', stopCondition: null, stopMessage: null });
      sendResponse({ ok: true });
      runLoopFrom(state.tabId, state.goal, state.step, state.history, '').catch((e) =>
        appendLog('Error resuming: ' + e.message)
      );
    })();
    return true;
  }

  if (msg?.type === 'ANSWER_USER_QUESTION') {
    (async () => {
      const { state } = await getStoredData();
      const ans = msg.answer || '';
      await appendLog(`User answered clarification: "${ans}"`);
      await updateState({ status: 'running', userQuestion: null });
      sendResponse({ ok: true });
      const history = [...state.history, { type: 'ask_user_answer', answer: ans }];
      runLoopFrom(state.tabId, state.goal, state.step, history, '').catch((e) =>
        appendLog('Error resuming: ' + e.message)
      );
    })();
    return true;
  }
});
