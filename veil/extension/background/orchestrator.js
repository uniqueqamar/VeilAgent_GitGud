// Agent Orchestrator for Veil Agent (SIH PS 26171)
// Implements Dual-Mode Architecture:
// 1. Autonomous Vision AI Agent Pipeline:
//    capture -> client-side ViT / face detection -> OffscreenCanvas solid black redaction ->
//    gate allowlist & SHA-256 receipt chaining -> server VLM planner -> validation -> execute
// 2. Instant On-Device Form Autofill Pipeline:
//    DOM capture -> FieldMatcher -> Encrypted Vault -> Sensitive Skip -> Approval Before Submit

if (typeof importScripts === 'function') {
  try {
    importScripts(
      '/workers/pii.js',
      '/workers/field-matcher.js',
      '/privacy/injection-shield.js',
      '/privacy/protocol-validator.js',
      '/privacy/vault.js',
      '/privacy/model-loader.js',
      '/privacy/vision-runner.js',
      '/privacy/redactor.js',
      '/privacy/gate.js'
    );
  } catch (e) {
    try {
      importScripts(
        '../workers/pii.js',
        '../workers/field-matcher.js',
        '../privacy/injection-shield.js',
        '../privacy/protocol-validator.js',
        '../privacy/vault.js',
        '../privacy/model-loader.js',
        '../privacy/vision-runner.js',
        '../privacy/redactor.js',
        '../privacy/gate.js'
      );
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
  schema_version: '2.0',
  active_profile: 'default',
  profiles: {
    default: {
      FULL_NAME: 'Tanisha Choudhary',
      FIRST_NAME: 'Tanisha',
      LAST_NAME: 'Choudhary',
      DOB: '2005-09-04',
      GENDER: 'Female',
      EMAIL: 'tanishachoudhary090405@gmail.com',
      MOBILE: '9876543210',
      ADDRESS_LINE1: 'Flat 402, Green Glen Heights, Outer Ring Road',
      CITY: 'Bengaluru',
      STATE: 'Karnataka',
      PIN: '560103',
      COUNTRY: 'India'
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
      agentMode: 'Balanced', // Default mode for vision agent
      showLast4: false
    });
    await sessionStore.set({ vault_passphrase: DEFAULT_PASSPHRASE });
  }
});

// Decrypt vault in memory / session storage only (never sent to disk unencrypted)
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

async function saveEncryptedVault(vaultObj) {
  memoryVault = vaultObj;
  const { vault_passphrase } = await sessionStore.get('vault_passphrase');
  const pass = vault_passphrase || DEFAULT_PASSPHRASE;

  if (globalThis.VeilVault?.encryptVault) {
    const encrypted = await globalThis.VeilVault.encryptVault(vaultObj, pass);
    await api.storage.local.set({ vault_encrypted: encrypted });
  }
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
      pendingSubmitAction: null,
      filledFields: [],
      skippedFields: [],
      missingFields: [],
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
      files: [
        'workers/pii.js',
        'privacy/injection-shield.js',
        'content/dom-capture.js',
        'content/executor.js',
        'content/floating-widget.js'
      ]
    });
    await new Promise((r) => setTimeout(r, 80));
    return true;
  } catch (err) {
    throw new Error(`Content script not available on active tab: ${err.message}`);
  }
}

// Invariant 4: Placeholder and Token Resolution
async function validateAndResolveValue(value, tabUrl) {
  if (value === null || value === undefined) return value;
  if (typeof value !== 'string') {
    throw new Error('Action rejected: value must be a string');
  }

  // Refuse to fill identity fields on unencrypted http:// pages
  const isPlainHttp =
    tabUrl &&
    tabUrl.startsWith('http:') &&
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
  const profile = globalThis.VeilVault?.getProfile
    ? globalThis.VeilVault.getProfile(vault)
    : (vault.profiles?.default || vault);

  // Direct match
  if (profile[normKey] !== undefined && profile[normKey] !== '') {
    return profile[normKey];
  }

  // Common aliases
  if (normKey === 'NAME' && profile.FULL_NAME) return profile.FULL_NAME;
  if (normKey === 'FULL_NAME' && profile.NAME) return profile.NAME;
  if (normKey === 'PHONE' && profile.MOBILE) return profile.MOBILE;
  if (normKey === 'MOBILE' && profile.PHONE) return profile.PHONE;

  // Composed values (DOB formats, address parts)
  if (globalThis.VeilVault?.compose) {
    const comp = globalThis.VeilVault.compose(normKey, profile);
    if (comp) return comp;
  }

  return '';
}

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

// Frame origin map for security and vault protection
const frameOriginsMap = new Map();

async function captureAllFrames(tabId, options = {}) {
  frameOriginsMap.clear();
  let frameSnapshots = [];

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

  if (frameSnapshots.length === 0) {
    const single = await api.tabs.sendMessage(tabId, { type: 'CAPTURE', mode: options.mode });
    if (single?.ok && single?.dom) {
      frameSnapshots = [{ frameId: 0, dom: single.dom }];
    }
  }

  if (frameSnapshots.length === 0) {
    throw new Error('no content script responding on active tab');
  }

  const topSnapshot = frameSnapshots.find((f) => f.frameId === 0 || f.dom?.isTop) || frameSnapshots[0];
  const topOrigin = topSnapshot.dom.origin || (new URL(topSnapshot.dom.url)).origin;
  frameOriginsMap.set(topSnapshot.frameId, topOrigin);

  const allNodes = [];
  const topViewport = topSnapshot.dom.viewport || [1280, 800];
  let totalSuspectText = 0;

  for (const f of frameSnapshots) {
    if (f.dom?.suspectTextCount) totalSuspectText += f.dom.suspectTextCount;
  }

  for (const node of (topSnapshot.dom.nodes || [])) {
    const qualifiedId = node.id.startsWith('f') ? node.id : `f${topSnapshot.frameId}:${node.id}`;
    allNodes.push({
      ...node,
      id: qualifiedId,
      frameId: topSnapshot.frameId,
      frameOrigin: topOrigin
    });
  }

  const childIframes = topSnapshot.dom.childFrames || [];
  const subframes = frameSnapshots.filter((f) => f !== topSnapshot);

  for (let i = 0; i < subframes.length; i++) {
    const sub = subframes[i];
    const subOrigin = sub.dom.origin || 'about:blank';
    frameOriginsMap.set(sub.frameId, subOrigin);

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

  const vw = topViewport[0];
  const vh = topViewport[1];
  allNodes.sort((a, b) => {
    const aInView = a.bbox[0] >= 0 && a.bbox[1] >= 0 && a.bbox[0] < vw && a.bbox[1] < vh;
    const bInView = b.bbox[0] >= 0 && b.bbox[1] >= 0 && b.bbox[0] < vw && b.bbox[1] < vh;
    if (aInView && !bInView) return -1;
    if (!aInView && bInView) return 1;
    return 0;
  });

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

// Execute single validated step or queue for approval
async function executeStep(tabId, action, rawAction, goal, step, history, nodes, options = {}) {
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

  const targetNode = nodes.find((n) => n.id === action.target_id);
  const isVisualOnly = (action.target_id && action.target_id.startsWith('vo')) || targetNode?.role === 'visual_only';

  if (isVisualOnly) {
    if (action.action === 'type') {
      const err = 'Action rejected: typing into visual_only nodes is strictly forbidden (Invariant 16)';
      await appendLog(err);
      await updateState({ status: 'error', error: err });
      return { error: err };
    }
  }

  const requiresApproval =
    action.action === 'submit' ||
    isSubmitAction(action, nodes) ||
    isRiskyClick(action, nodes) ||
    isVisualOnly;

  if (requiresApproval && !options.preApproved) {
    await updateState({
      status: 'waiting_approval',
      pendingAction: action,
      rawAction,
      goal,
      step,
      history,
      tabId,
      approvalReason: isVisualOnly
        ? `Visual-only element click at (${targetNode?.bbox?.slice(0, 2)?.join(', ')}) requires user approval.`
        : `High-impact action: ${action.action} on ${action.target_id || 'page'}. Confirm execution?`
    });
    await appendLog(`Approval required: ${action.action} on ${action.target_id || 'page'}. Awaiting confirmation.`);
    return { waitingApproval: true };
  }

  // Format action for content script execution
  let targetFrameId = 0;
  let localTargetId = action.target_id;
  if (action.target_id) {
    const m = action.target_id.match(/^f(\d+):(.*)$/);
    if (m) {
      targetFrameId = parseInt(m[1], 10);
      localTargetId = m[2];
    }
  }

  const actionForContent = {
    ...action,
    target_id: localTargetId
  };

  const msgOpts = targetFrameId > 0 ? { frameId: targetFrameId } : undefined;
  let result;
  try {
    result = await api.tabs.sendMessage(tabId, {
      type: 'EXECUTE',
      action: actionForContent
    }, msgOpts);
  } catch (sendErr) {
    result = await api.tabs.sendMessage(tabId, {
      type: 'EXECUTE',
      action: actionForContent
    });
  }

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

  // Accumulate filled field for Review-Before-Submit table
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

  history.push(rawAction);
  await updateState({ step: step + 1, history });
  return { ok: true };
}

// -------------------------------------------------------------
// PIPELINE 1: Autonomous Vision AI Agent Execution Loop (SIH PS 26171)
// -------------------------------------------------------------
async function runAgent(goal = 'Complete Web Task') {
  await clearLogs();
  await appendLog(`[Vision Agent] Starting goal: "${goal}"`);

  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    await appendLog('Error: no active tab found.');
    await updateState({ status: 'error', error: 'No active tab found' });
    return;
  }

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
    await appendLog(`Domain approval required for: ${domain}`);
    return;
  }

  const { showLast4 = false } = await api.storage.local.get('showLast4');
  if (globalThis.VeilVault?.createSessionTokenizer) {
    currentTokenizer = globalThis.VeilVault.createSessionTokenizer({ showLast4 });
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

async function runLoopFrom(tabId, goal, startStep, history, tabUrl) {
  if (!tabUrl) {
    try {
      const tab = await api.tabs.get(tabId);
      tabUrl = tab?.url || '';
    } catch (_) {}
  }

  for (let step = startStep; step <= MAX_STEPS; step++) {
    const { state } = await getStoredData();
    if (state.status === 'stopped') {
      await appendLog('Agent stopped.');
      return;
    }

    try {
      await ensureContentScript(tabId);
    } catch (e) {
      await appendLog('Error: ' + e.message);
      await updateState({ status: 'error', error: e.message });
      return;
    }

    const { agentMode = 'Balanced' } = await api.storage.local.get('agentMode');
    let screenshotData = null;
    let redactionManifest = [];
    let effectiveMode = agentMode;
    let redactResult = null;

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

    // Step A: Visual Perception & Redaction
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

        // Step B: Client-side UI Context Detection (ViT / YOLOX via ONNX Web)
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
              await appendLog(
                `Vision ViT detected ${uiResult.visualOnlyNodes.length} visual element(s). Visual context accuracy: ${uiResult.contextAccuracy}`
              );
            }
          } catch (uiErr) {
            await appendLog(`UI detector degraded to DOM-only: ${uiErr.message}`);
          }
        }

        // Cache view in memory for user inspection ("What the server sees")
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

    // Step C: Layered Local Field Matcher (Local-first, fallback to Server VLM)
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
            const currentVault = await getDecryptedVault();
            const val = getVaultValue(currentVault, vaultKey);
            if (val) {
              const isLowStakes = /newsletter|subscribe|contact|feedback|survey/i.test(cap.dom.title || '');
              if (isLowStakes && globalThis.VeilVault?.isHighSensitivity && globalThis.VeilVault.isHighSensitivity(vaultKey)) {
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

    // Step D: Send Sanitized Context via Privacy Gate to Server VLM Planner
    const ALLOWED_NODE_FIELDS = new Set([
      'id', 'tag', 'role', 'type', 'label', 'text', 'autocomplete', 'sensitive', 'bbox', 'pii'
    ]);
    const cleanNodes = (cap.dom.nodes || []).map((node) => {
      const cleanNode = {};
      for (const k of Object.keys(node)) {
        if (ALLOWED_NODE_FIELDS.has(k)) {
          cleanNode[k] = node[k];
        }
      }
      if (typeof cleanNode.label === 'string' && cleanNode.label.length > 40) {
        cleanNode.label = cleanNode.label.slice(0, 40);
      }
      if (typeof cleanNode.text === 'string' && cleanNode.text.length > 500) {
        cleanNode.text = cleanNode.text.slice(0, 500);
      }
      return cleanNode;
    });

    const cleanDom = {
      url: cap.dom.url,
      title: cap.dom.title,
      viewport: cap.dom.viewport,
      scrollY: cap.dom.scrollY,
      nodes: cleanNodes
    };

    const ALLOWED_HISTORY_FIELDS = new Set([
      'type', 'action', 'target_id', 'coords', 'value', 'text', 'question', 'reason', 'skipped'
    ]);
    const cleanHistory = (history || []).map((item) => {
      const cleanItem = {};
      for (const k of Object.keys(item)) {
        if (ALLOWED_HISTORY_FIELDS.has(k)) {
          cleanItem[k] = item[k];
        }
      }
      return cleanItem;
    });

    const payload = {
      goal,
      step,
      dom: cleanDom,
      screenshot: screenshotData,
      redactions: redactionManifest,
      cleared_media: redactResult?.clearedMediaIds || [],
      vision: redactResult?.vision || null,
      history: cleanHistory,
      mode: effectiveMode,
      suspect_text_count: cap.dom.suspectTextCount || 0
    };

    let serverResponse;
    try {
      serverResponse = await globalThis.sendSanitized('/plan', payload, (receipt) => {
        appendLog(`gate sent ${receipt.bytes} bytes (${effectiveMode} mode) [receipt: ${receipt.hash.slice(0, 10)}...]`);
      });
    } catch (e) {
      const errMsg = e.message.includes('Failed to fetch')
        ? 'server down (connection failed to http://127.0.0.1:8000)'
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

    let respType = serverResponse.type;
    if (!respType && serverResponse.action) {
      if (serverResponse.action === 'done') respType = 'done';
      else if (serverResponse.action === 'fail') respType = 'fail';
      else respType = 'action';
    }

    if (respType === 'answer') {
      const rawText = serverResponse.text || '';
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

    if (respType === 'done') {
      const doneReason = serverResponse.reason || 'task completed';
      await appendLog(`step ${step} [${latency}ms]: Done: ${doneReason}`);
      await updateState({ status: 'done', step, reason: doneReason });
      return;
    }

    if (respType === 'fail') {
      const failReason = serverResponse.reason || 'task failed';
      await appendLog(`step ${step} [${latency}ms]: Server returned fail: ${failReason}`);
      await updateState({ status: 'error', error: failReason, step });
      return;
    }

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

    if (respType === 'action') {
      const serverAction = serverResponse;
      if (!serverAction || !WHITELIST_ACTIONS.includes(serverAction.action)) {
        const err = `Action rejected: untrusted action "${serverAction?.action}"`;
        await appendLog(err);
        await updateState({ status: 'error', error: err });
        return;
      }

      await appendLog(`step ${step} [${latency}ms]: ${serverAction.action} ${serverAction.target_id ?? ''} - ${serverAction.reason ?? ''}`);

      const rawAction = { ...serverAction };
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
      if (stepResult.waitingApproval) return;
      if (stepResult.stale) continue;
    }
  }

  await appendLog('Stopped: maximum steps (8) reached.');
  await updateState({ status: 'stopped' });
}

// -------------------------------------------------------------
// PIPELINE 2: Instant On-Device Form Autofill Pipeline
// -------------------------------------------------------------
async function runAutofill(goal = 'Autofill Form') {
  await clearLogs();
  await appendLog('Starting form autofill...');

  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    await appendLog('Error: No active browser tab found.');
    await updateState({ status: 'error', error: 'No active tab found' });
    return;
  }

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
    await appendLog(`Domain approval required for: ${domain}`);
    return;
  }

  await ensureContentScript(tab.id);

  const vault = await getDecryptedVault();
  const profile = globalThis.VeilVault?.getProfile ? globalThis.VeilVault.getProfile(vault) : (vault.profiles?.default || vault);

  await updateState({
    status: 'running',
    goal,
    tabId: tab.id,
    filledFields: [],
    skippedFields: [],
    missingFields: [],
    pendingSubmitAction: null,
    error: null
  });

  let cap;
  try {
    cap = await captureAllFrames(tab.id);
  } catch (err) {
    await appendLog(`Capture failed: ${err.message}`);
    await updateState({ status: 'error', error: err.message });
    return;
  }

  const nodes = cap?.dom?.nodes || [];
  await appendLog(`Found ${nodes.length} actionable elements on screen.`);

  const filledList = [];
  const skippedList = [];
  const missingList = [];
  let submitNode = null;

  for (const node of nodes) {
    const tag = (node.tag || '').toLowerCase();
    const type = (node.type || '').toLowerCase();
    const label = (node.label || node.text || '').trim();

    if (tag === 'button' || type === 'submit') {
      if (/submit|apply|register|complete|proceed|send/i.test(label) || type === 'submit') {
        if (!submitNode) submitNode = node;
      }
      continue;
    }

    if (!['input', 'select', 'textarea'].includes(tag)) continue;
    if (['button', 'submit', 'reset', 'hidden', 'image'].includes(type)) continue;

    const match = globalThis.FieldMatcher?.matchField ? globalThis.FieldMatcher.matchField(node) : null;

    if (match && match.isSensitive) {
      skippedList.push({
        nodeId: node.id,
        label: label || 'Sensitive Field',
        type: match.sensitiveType || 'SENSITIVE',
        reason: 'Privacy Policy: sensitive data is never filled automatically'
      });
      await appendLog(`🛡️ [SKIPPED] ${label || node.id} (${match.sensitiveType || 'SENSITIVE'})`);
      continue;
    }

    if (node.sensitive === true) {
      skippedList.push({
        nodeId: node.id,
        label: label || 'Sensitive Input',
        type: 'PASSWORD/SENSITIVE',
        reason: 'Sensitive password/credential field skipped'
      });
      await appendLog(`🛡️ [SKIPPED] ${label || node.id} (Password/Credential)`);
      continue;
    }

    if (match && match.vaultKey) {
      const val = getVaultValue(vault, match.vaultKey);
      if (val !== undefined && val !== null && String(val).trim() !== '') {
        const strVal = String(val);
        const actionType = tag === 'select' ? 'select' : 'type';

        let targetFrameId = 0;
        let localTargetId = node.id;
        const m = node.id.match(/^f(\d+):(.*)$/);
        if (m) {
          targetFrameId = parseInt(m[1], 10);
          localTargetId = m[2];
        }

        try {
          const msgOpts = targetFrameId > 0 ? { frameId: targetFrameId } : undefined;
          const execRes = await api.tabs.sendMessage(tab.id, {
            type: 'EXECUTE',
            action: {
              action: actionType,
              target_id: localTargetId,
              value: strVal
            }
          }, msgOpts);

          if (execRes?.ok) {
            filledList.push({
              nodeId: node.id,
              label: label || match.vaultKey,
              value: strVal,
              vaultKey: match.vaultKey,
              confidence: match.confidence
            });
            await appendLog(`Filled: "${label || node.id}" <- [${match.vaultKey}]`);
          } else {
            await appendLog(`Failed to fill: "${label || node.id}": ${execRes?.error || 'Execution failed'}`);
          }
        } catch (fillErr) {
          await appendLog(`Error filling ${node.id}: ${fillErr.message}`);
        }
      } else {
        missingList.push({
          nodeId: node.id,
          label: label || match.vaultKey,
          vaultKey: match.vaultKey
        });
        await appendLog(`Missing Vault key: "${match.vaultKey}" for field "${label || node.id}"`);
      }
    }
  }

  if (submitNode && filledList.length > 0) {
    await updateState({
      status: 'waiting_approval',
      pendingSubmitAction: {
        action: 'click',
        target_id: submitNode.id,
        label: submitNode.label || submitNode.text || 'Submit'
      },
      filledFields: filledList,
      skippedFields: skippedList,
      missingFields: missingList
    });
    await appendLog(`\nAutofill Completed: ${filledList.length} fields filled, ${skippedList.length} sensitive skipped.`);
    await appendLog(`Submit button identified. Awaiting user approval to submit.`);
  } else {
    await updateState({
      status: 'done',
      filledFields: filledList,
      skippedFields: skippedList,
      missingFields: missingList,
      reason: `Autofilled ${filledList.length} fields. ${skippedList.length} sensitive skipped.`
    });
    await appendLog(`\nAutofill Finished: ${filledList.length} fields filled. ${skippedList.length} sensitive fields skipped.`);
  }
}

// -------------------------------------------------------------
// Message Router
// -------------------------------------------------------------
api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'RUN') {
    runAgent(msg.goal || 'Complete Web Task').catch((e) => appendLog('Error: ' + e.message));
    sendResponse({ ok: true });
    return false;
  }

  if (msg?.type === 'RUN_AUTOFILL') {
    runAutofill(msg.goal || 'Autofill Form').catch((e) => appendLog('Error: ' + e.message));
    sendResponse({ ok: true });
    return false;
  }

  if (msg?.type === 'STOP') {
    updateState({ status: 'stopped', pendingAction: null, pendingSubmitAction: null }).then(() => {
      appendLog('Process stopped by user.');
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg?.type === 'SET_MODE') {
    (async () => {
      const mode = msg.mode || 'Balanced';
      await api.storage.local.set({ agentMode: mode });
      await appendLog(`Agent mode updated to: ${mode}`);
      sendResponse({ ok: true, mode });
    })();
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
      if (state.goal && state.goal.includes('Autofill')) {
        runAutofill(state.goal).catch((e) => appendLog('Error: ' + e.message));
      } else {
        runAgent(state.goal).catch((e) => appendLog('Error: ' + e.message));
      }
    })();
    return true;
  }

  if (msg?.type === 'APPROVE_ACTION') {
    (async () => {
      const { state } = await getStoredData();
      if (state.status !== 'waiting_approval' || !state.pendingAction) {
        sendResponse({ ok: false, error: 'no pending action approval' });
        return;
      }

      await appendLog(`Approved action: ${state.pendingAction.action} on ${state.pendingAction.target_id}`);
      await updateState({ status: 'running' });

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
        const err = result?.error ?? 'Execution error';
        await appendLog('Approved action failed: ' + err);
        await updateState({ status: 'error', error: err });
        sendResponse({ ok: false, error: err });
        return;
      }

      const history = state.history || [];
      if (state.rawAction) history.push(state.rawAction);
      const nextStep = (state.step || 1) + 1;
      await updateState({ step: nextStep, history, pendingAction: null });
      sendResponse({ ok: true });

      runLoopFrom(state.tabId, state.goal, nextStep, history, null).catch((e) => appendLog('Error: ' + e.message));
    })();
    return true;
  }

  if (msg?.type === 'REJECT_ACTION') {
    (async () => {
      await appendLog('Action rejected by user. Run stopped.');
      await updateState({ status: 'stopped', pendingAction: null });
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.type === 'APPROVE_SUBMIT') {
    (async () => {
      const { state } = await getStoredData();
      if (!state.pendingSubmitAction || !state.tabId) {
        sendResponse({ ok: false, error: 'No pending submit action' });
        return;
      }

      await appendLog('Submitting form upon user approval...');
      let targetFrameId = 0;
      let localTargetId = state.pendingSubmitAction.target_id;
      const m = localTargetId.match(/^f(\d+):(.*)$/);
      if (m) {
        targetFrameId = parseInt(m[1], 10);
        localTargetId = m[2];
      }

      try {
        const msgOpts = targetFrameId > 0 ? { frameId: targetFrameId } : undefined;
        await api.tabs.sendMessage(state.tabId, {
          type: 'EXECUTE',
          action: { action: 'click', target_id: localTargetId }
        }, msgOpts);

        await appendLog('Form submitted successfully.');
        await updateState({
          status: 'done',
          pendingSubmitAction: null,
          reason: 'Form submitted successfully!'
        });
        sendResponse({ ok: true });
      } catch (err) {
        await appendLog(`Submit click failed: ${err.message}`);
        await updateState({ status: 'error', error: err.message, pendingSubmitAction: null });
        sendResponse({ ok: false, error: err.message });
      }
    })();
    return true;
  }

  if (msg?.type === 'SKIP_SUBMIT') {
    (async () => {
      await appendLog('Submission canceled by user. Form fields remain filled.');
      await updateState({
        status: 'done',
        pendingSubmitAction: null,
        reason: 'Form filled without submitting'
      });
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.type === 'GET_INSPECTION_DATA' || msg?.type === 'GET_SERVER_VIEW') {
    sendResponse({ ok: true, data: lastServerInspectionView, view: lastServerInspectionView });
    return false;
  }

  if (msg?.type === 'GET_RECEIPTS') {
    (async () => {
      const data = await sessionStore.get(['receipt_chain', 'latest_receipt']);
      sendResponse({
        ok: true,
        chain: data.receipt_chain || [],
        latest: data.latest_receipt || null
      });
    })();
    return true;
  }

  if (msg?.type === 'GET_VAULT') {
    (async () => {
      const vault = await getDecryptedVault();
      const profile = globalThis.VeilVault?.getProfile ? globalThis.VeilVault.getProfile(vault) : (vault.profiles?.default || vault);
      sendResponse({ ok: true, profile });
    })();
    return true;
  }

  if (msg?.type === 'SAVE_VAULT') {
    (async () => {
      const updatedProfile = msg.profile || {};
      const vault = await getDecryptedVault();
      vault.profiles = vault.profiles || {};
      vault.profiles.default = { ...(vault.profiles.default || {}), ...updatedProfile };
      await saveEncryptedVault(vault);
      await appendLog(`Vault updated with ${Object.keys(updatedProfile).length} fields.`);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.type === 'CHECK_SERVER') {
    (async () => {
      if (globalThis.VeilGate?.checkServerHealth) {
        const res = await globalThis.VeilGate.checkServerHealth();
        sendResponse(res);
      } else {
        sendResponse({ ok: true, connected: false });
      }
    })();
    return true;
  }

  if (msg?.type === 'GET_STATE') {
    (async () => {
      const stored = await getStoredData();
      const { agentMode = 'Balanced' } = await api.storage.local.get('agentMode');
      sendResponse({
        ok: true,
        state: stored.state,
        logs: stored.logs,
        mode: agentMode,
        hasInspection: !!lastServerInspectionView
      });
    })();
    return true;
  }
});
