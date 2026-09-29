// Orchestrator for Veil Agent
// Implements the Privacy-Preserving Form Autofill Pipeline:
// 1. One-time setup: User fills vault with details
// 2. Form Autofill: Agent reads form -> matches fields to vault keys -> fills automatically
// 3. Sensitive fields: Password/Aadhaar/PAN -> strictly skipped
// 4. Submit: Asks for user approval before submitting

if (typeof importScripts === 'function') {
  try {
    importScripts('/workers/pii.js', '/workers/field-matcher.js', '/privacy/injection-shield.js', '/privacy/vault.js');
  } catch (e) {
    try {
      importScripts('../workers/pii.js', '../workers/field-matcher.js', '../privacy/injection-shield.js', '../privacy/vault.js');
    } catch (e2) {
      console.error('Failed to import background scripts:', e2);
    }
  }
}

const api = globalThis.browser ?? globalThis.chrome;
const sessionStore = api.storage.session ?? api.storage.local;

const DEFAULT_PASSPHRASE = 'veil-local-key-passphrase';
const DEFAULT_VAULT = globalThis.VeilVault?.DEFAULT_PROFILES || {
  schema_version: '2.0',
  active_profile: 'default',
  profiles: {
    default: {
      FULL_NAME: 'Tanisha Choudhary',
      FIRST_NAME: 'Tanisha',
      LAST_NAME: 'Choudhary',
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

let memoryVault = null;

// Initialize encrypted vault on install if not present
api.runtime.onInstalled.addListener(async () => {
  const existing = await api.storage.local.get('vault_encrypted');
  if (!existing?.vault_encrypted && globalThis.VeilVault?.encryptVault) {
    const encrypted = await globalThis.VeilVault.encryptVault(DEFAULT_VAULT, DEFAULT_PASSPHRASE);
    await api.storage.local.set({
      vault_encrypted: encrypted,
      approvedDomains: ['localhost', '127.0.0.1']
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
      status: 'idle',
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
      files: ['workers/pii.js', 'privacy/injection-shield.js', 'content/dom-capture.js', 'content/executor.js']
    });
    await new Promise((r) => setTimeout(r, 100));
    return true;
  } catch (err) {
    throw new Error(`Content script not available on active tab: ${err.message}`);
  }
}

function getVaultValue(vault, key) {
  if (!vault || !key) return '';
  const normKey = key.toUpperCase().trim();
  const profile = globalThis.VeilVault?.getProfile ? globalThis.VeilVault.getProfile(vault) : (vault.profiles?.default || vault);

  // Direct match
  if (profile[normKey] !== undefined && profile[normKey] !== '') {
    return profile[normKey];
  }

  // Composed values
  if (globalThis.VeilVault?.compose) {
    const comp = globalThis.VeilVault.compose(normKey, profile);
    if (comp) return comp;
  }

  return '';
}

async function captureAllFrames(tabId) {
  let frameSnapshots = [];

  if (api.scripting?.executeScript) {
    try {
      const results = await api.scripting.executeScript({
        target: { tabId, allFrames: true },
        func: () => {
          return globalThis.__veil?.capture ? globalThis.__veil.capture() : null;
        }
      });
      frameSnapshots = (results || [])
        .filter((r) => r && r.result)
        .map((r) => ({ frameId: r.frameId ?? 0, dom: r.result }));
    } catch (_) {}
  }

  if (frameSnapshots.length === 0) {
    const res = await api.tabs.sendMessage(tabId, { type: 'CAPTURE' });
    if (res?.ok && res.dom) {
      frameSnapshots.push({ frameId: 0, dom: res.dom });
    }
  }

  const allNodes = [];
  for (const f of frameSnapshots) {
    for (const node of (f.dom?.nodes || [])) {
      const qualifiedId = node.id.startsWith('f') ? node.id : `f${f.frameId}:${node.id}`;
      allNodes.push({
        ...node,
        id: qualifiedId,
        frameId: f.frameId
      });
    }
  }

  return {
    ok: true,
    nodes: allNodes
  };
}

// Main Autofill Pipeline:
// 1. Read Form -> 2. Match to Vault -> 3. Skip Sensitive -> 4. Ask Approval for Submit
async function runAutofill(goal = 'Autofill Form') {
  await clearLogs();
  await appendLog('🚀 Starting Veil Form Autofill...');

  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    await appendLog('❌ Error: No active browser tab found.');
    await updateState({ status: 'error', error: 'No active tab found' });
    return;
  }

  // Optional domain approval check
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
    await appendLog(`🔒 Domain approval required for: ${domain}`);
    return;
  }

  await ensureContentScript(tab.id);

  // Get user's Vault dataset
  const vault = await getDecryptedVault();
  const profile = globalThis.VeilVault?.getProfile ? globalThis.VeilVault.getProfile(vault) : (vault.profiles?.default || vault);

  await updateState({
    status: 'running',
    goal,
    tabId: tab.id,
    filledFields: [],
    skippedFields: [],
    missingFields: [],
    pendingSubmitAction: null
  });

  // Capture DOM nodes
  const cap = await captureAllFrames(tab.id);
  const nodes = cap.nodes || [];
  await appendLog(`🔍 Form Scanner: Found ${nodes.length} page elements.`);

  const filledList = [];
  const skippedList = [];
  const missingList = [];
  let detectedSubmitBtn = null;

  // Process all input, select, textarea elements
  for (const node of nodes) {
    const tag = (node.tag || '').toLowerCase();
    const type = (node.type || '').toLowerCase();

    // Check if this is a Submit / Action button
    if (
      node.isSubmit ||
      type === 'submit' ||
      (tag === 'button' && /submit|apply|register|send|next|proceed|save/i.test(node.label || '')) ||
      (tag === 'input' && (type === 'button' || type === 'submit') && /submit|apply|register|send|next/i.test(node.label || ''))
    ) {
      if (!detectedSubmitBtn) {
        detectedSubmitBtn = node;
      }
      continue;
    }

    // Only process input, textarea, select
    if (!['input', 'textarea', 'select'].includes(tag)) continue;
    if (type === 'hidden' || type === 'button' || type === 'reset') continue;

    // STEP 3: PASSWORD / AADHAAR / PAN -> SKIPPED (SENSITIVE)
    const match = globalThis.FieldMatcher ? globalThis.FieldMatcher.matchField(node) : null;
    const isSensitiveField =
      node.sensitive ||
      type === 'password' ||
      match?.isSensitive ||
      /password|aadhaar|aadhar|pan card|pan number|cvv|otp/i.test(node.label || '') ||
      /password|aadhaar|aadhar|pan|cvv|otp/i.test(node.name || '');

    if (isSensitiveField) {
      const fieldDesc = node.label || node.placeholder || node.name || 'Sensitive Credential';
      const sensitiveType = match?.sensitiveType || (type === 'password' ? 'PASSWORD' : 'AADHAAR / PAN');
      skippedList.push({
        id: node.id,
        label: fieldDesc,
        type: sensitiveType,
        reason: 'Password/Aadhaar/PAN are never autofilled for security'
      });
      await appendLog(`🛡️ [SKIPPED SENSITIVE] "${fieldDesc}" (${sensitiveType}) - safely left untouched.`);
      continue;
    }

    // STEP 2: AGENT READS FORM -> MATCHES FIELDS TO VAULT KEYS -> FILLS AUTOMATICALLY
    if (match && match.vaultKey) {
      const vaultKey = match.vaultKey;
      const vaultValue = getVaultValue(vault, vaultKey);

      if (vaultValue) {
        // Execute fill action
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
          await api.tabs.sendMessage(tab.id, {
            type: 'EXECUTE',
            action: {
              action: actionType,
              target_id: localTargetId,
              value: String(vaultValue)
            }
          }, msgOpts);

          const maskedVal = globalThis.VeilVault?.maskValue
            ? globalThis.VeilVault.maskValue(String(vaultValue), vaultKey.toLowerCase())
            : String(vaultValue);

          filledList.push({
            id: node.id,
            label: node.label || vaultKey,
            key: vaultKey,
            value: String(vaultValue),
            masked: maskedVal
          });

          await appendLog(`✅ [FILLED] "${node.label || vaultKey}" → ${vaultKey}: "${maskedVal}"`);
        } catch (err) {
          await appendLog(`⚠️ [FILL FAILED] "${node.label || node.id}": ${err.message}`);
        }
      } else {
        missingList.push({
          id: node.id,
          label: node.label || vaultKey,
          key: vaultKey
        });
        await appendLog(`ℹ️ [VAULT EMPTY] "${node.label || vaultKey}" matched key ${vaultKey}, but no value entered in your Vault.`);
      }
    } else {
      await appendLog(`ℹ️ [UNMATCHED] Field "${node.label || node.name || node.id}" (no matching vault key).`);
    }
  }

  // STEP 4: SUBMIT -> ASKS FOR APPROVAL
  if (detectedSubmitBtn) {
    const submitLabel = detectedSubmitBtn.label || 'Submit Form';
    await updateState({
      status: 'waiting_submit_approval',
      filledFields: filledList,
      skippedFields: skippedList,
      missingFields: missingList,
      pendingSubmitAction: {
        action: 'click',
        target_id: detectedSubmitBtn.id
      },
      submitLabel,
      tabId: tab.id
    });
    await appendLog(`\n📋 Form Autofill Finished: ${filledList.length} fields filled, ${skippedList.length} sensitive skipped.`);
    await appendLog(`✋ Ready to submit! Click "Approve & Submit" in popup to finalize.`);
  } else {
    await updateState({
      status: 'done',
      filledFields: filledList,
      skippedFields: skippedList,
      missingFields: missingList,
      reason: `Autofilled ${filledList.length} fields. ${skippedList.length} sensitive fields skipped.`
    });
    await appendLog(`\n🎉 Autofill Complete! Filled ${filledList.length} fields. ${skippedList.length} sensitive fields skipped.`);
  }
}

// Runtime message dispatcher
api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'RUN' || msg?.type === 'RUN_AUTOFILL') {
    runAutofill(msg.goal || 'Autofill Form').catch((e) => appendLog('Error: ' + e.message));
    sendResponse({ ok: true });
    return false;
  }

  if (msg?.type === 'STOP') {
    updateState({ status: 'stopped', pendingSubmitAction: null }).then(() => {
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
      runAutofill(state.goal).catch((e) => appendLog('Error: ' + e.message));
    })();
    return true;
  }

  // STEP 4: User Approves Submission
  if (msg?.type === 'APPROVE_SUBMIT') {
    (async () => {
      const { state } = await getStoredData();
      if (!state.pendingSubmitAction || !state.tabId) {
        sendResponse({ ok: false, error: 'No pending submit action' });
        return;
      }

      await appendLog('🚀 Submitting form upon user approval...');
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

        await appendLog('✅ Form submitted successfully!');
        await updateState({
          status: 'done',
          pendingSubmitAction: null,
          reason: 'Form submitted successfully!'
        });
        sendResponse({ ok: true });
      } catch (err) {
        await appendLog(`⚠️ Submit click failed: ${err.message}`);
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

  // STEP 1: Vault Management API
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
      await appendLog(`💾 Vault updated with ${Object.keys(updatedProfile).length} fields.`);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.type === 'GET_STATE') {
    (async () => {
      const stored = await getStoredData();
      sendResponse({ ok: true, state: stored.state, logs: stored.logs });
    })();
    return true;
  }
});
