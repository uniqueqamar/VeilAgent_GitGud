// UI Controller for Veil Agent Popup (SIH PS 26171)
// Handles:
// 1. Instant Form Autofill & Review-Before-Submit
// 2. Autonomous Vision AI Agent & Server Connection
// 3. "What the Server Sees" Visual Redaction Inspection Modal
// 4. Cryptographic SHA-256 Audit Receipt Export
// 5. Encrypted Vault Profile Management

const api = globalThis.browser ?? globalThis.chrome;

// Navigation Tabs
const tabAutofill = document.getElementById('tab-autofill');
const tabVision = document.getElementById('tab-vision');
const tabVault = document.getElementById('tab-vault');
const viewAutofill = document.getElementById('view-autofill');
const viewVision = document.getElementById('view-vision');
const viewVault = document.getElementById('view-vault');

// Header Status
const statusBadge = document.getElementById('status-badge');

// Autofill Controls
const btnRun = document.getElementById('btn-run');
const btnStop = document.getElementById('btn-stop');
const logViewer = document.getElementById('log-viewer');
const btnClearLog = document.getElementById('btn-clear-log');
const submitApprovalBox = document.getElementById('submit-approval-box');
const reviewTableBody = document.getElementById('review-table-body');
const btnApproveSubmit = document.getElementById('btn-approve-submit');
const btnSkipSubmit = document.getElementById('btn-skip-submit');

// Domain Approval Box
const domainApprovalBox = document.getElementById('domain-approval-box');
const domainApprovalDesc = document.getElementById('domain-approval-desc');
const btnApproveDomain = document.getElementById('btn-approve-domain');
const btnCancelDomain = document.getElementById('btn-cancel-domain');

// Vision Agent Controls
const serverStatusDot = document.getElementById('server-status-dot');
const serverStatusText = document.getElementById('server-status-text');
const btnCheckServer = document.getElementById('btn-check-server');
const modeStrict = document.getElementById('mode-strict');
const modeBalanced = document.getElementById('mode-balanced');
const modeOpen = document.getElementById('mode-open');
const agentGoal = document.getElementById('agent-goal');
const btnRunVision = document.getElementById('btn-run-vision');
const btnStopVision = document.getElementById('btn-stop-vision');
const actionApprovalBox = document.getElementById('action-approval-box');
const actionApprovalDesc = document.getElementById('action-approval-desc');
const btnApproveAction = document.getElementById('btn-approve-action');
const btnRejectAction = document.getElementById('btn-reject-action');
const btnOpenInspect = document.getElementById('btn-open-inspect');
const btnExportReceipts = document.getElementById('btn-export-receipts');
const visionLogViewer = document.getElementById('vision-log-viewer');
const btnClearVisionLog = document.getElementById('btn-clear-vision-log');

// Telemetry
const telLatency = document.getElementById('telemetry-latency');
const telBytes = document.getElementById('telemetry-bytes');
const telRedactions = document.getElementById('telemetry-redactions');
const telStep = document.getElementById('telemetry-step');

// Inspection Modal Elements
const inspectModal = document.getElementById('inspect-modal');
const closeModalBtn = document.getElementById('close-modal-btn');
const tabOverlays = document.getElementById('tab-overlays');
const tabRedacted = document.getElementById('tab-redacted');
const tabOriginal = document.getElementById('tab-original');
const tabManifest = document.getElementById('tab-manifest');
const panelOverlays = document.getElementById('panel-overlays');
const panelRedacted = document.getElementById('panel-redacted');
const panelOriginal = document.getElementById('panel-original');
const panelManifest = document.getElementById('panel-manifest');
const overlayCanvas = document.getElementById('overlay-canvas');
const overlayPlaceholder = document.getElementById('overlay-placeholder');
const redactedImg = document.getElementById('redacted-img');
const redactedPlaceholder = document.getElementById('redacted-placeholder');
const originalImg = document.getElementById('original-img');
const originalPlaceholder = document.getElementById('original-placeholder');
const manifestContent = document.getElementById('manifest-content');

// Vault Elements
const btnSaveVault = document.getElementById('btn-save-vault');
const btnSaveVaultBottom = document.getElementById('btn-save-vault-bottom');
const btnLoadDemo = document.getElementById('btn-load-demo');
const toastEl = document.getElementById('toast');

const VAULT_KEYS = [
  'FULL_NAME', 'FIRST_NAME', 'LAST_NAME', 'DOB', 'GENDER', 'FATHER_NAME', 'MOTHER_NAME',
  'NATIONALITY', 'CATEGORY',
  'EMAIL', 'MOBILE', 'ALT_MOBILE', 'WORK_EMAIL',
  'ADDRESS_LINE1', 'ADDRESS_LINE2', 'CITY', 'DISTRICT', 'STATE', 'PIN', 'COUNTRY',
  'PASSWORD', 'AADHAAR', 'PAN', 'PASSPORT'
];

const DEMO_PROFILE = {
  FULL_NAME: 'Tanisha Choudhary',
  FIRST_NAME: 'Tanisha',
  LAST_NAME: 'Choudhary',
  DOB: '2005-09-04',
  GENDER: 'Female',
  FATHER_NAME: 'Rajesh Choudhary',
  MOTHER_NAME: 'Sunita Choudhary',
  NATIONALITY: 'Indian',
  CATEGORY: 'General',
  EMAIL: 'tanishachoudhary090405@gmail.com',
  MOBILE: '9876543210',
  ALT_MOBILE: '9876543211',
  WORK_EMAIL: 'tanisha@work.com',
  ADDRESS_LINE1: 'Flat 402, Green Glen Heights, Outer Ring Road',
  ADDRESS_LINE2: 'Near Bellandur Junction',
  CITY: 'Bengaluru',
  DISTRICT: 'Bengaluru Urban',
  STATE: 'Karnataka',
  PIN: '560103',
  COUNTRY: 'India',
  PASSWORD: 'DemoPassword#2026',
  AADHAAR: '3675 9834 6012',
  PAN: 'ABCDE1234F',
  PASSPORT: 'P1234567'
};

function showToast(msg) {
  if (!toastEl) return;
  toastEl.textContent = msg;
  toastEl.style.display = 'block';
  setTimeout(() => {
    toastEl.style.display = 'none';
  }, 2200);
}

// Tab Switching
function switchTab(target) {
  tabAutofill.classList.remove('active');
  tabVision.classList.remove('active');
  tabVault.classList.remove('active');
  viewAutofill.classList.remove('active');
  viewVision.classList.remove('active');
  viewVault.classList.remove('active');

  if (target === 'autofill') {
    tabAutofill.classList.add('active');
    viewAutofill.classList.add('active');
  } else if (target === 'vision') {
    tabVision.classList.add('active');
    viewVision.classList.add('active');
    checkServerHealth();
  } else if (target === 'vault') {
    tabVault.classList.add('active');
    viewVault.classList.add('active');
    loadVaultData();
  }
}

tabAutofill.onclick = () => switchTab('autofill');
tabVision.onclick = () => switchTab('vision');
tabVault.onclick = () => switchTab('vault');

// Check Server Health
async function checkServerHealth() {
  serverStatusText.textContent = 'Checking...';
  api.runtime.sendMessage({ type: 'CHECK_SERVER' }, (res) => {
    if (res?.connected) {
      serverStatusDot.className = 'status-dot online';
      const model = res.model ? ` (${res.model.backend || 'Deterministic'})` : '';
      serverStatusText.textContent = `Server: Connected${model}`;
    } else {
      serverStatusDot.className = 'status-dot offline';
      serverStatusText.textContent = 'Server: Offline (127.0.0.1:8000)';
    }
  });
}
btnCheckServer.onclick = checkServerHealth;

// Mode Switching (Strict / Balanced / Open)
function setModeUI(mode) {
  modeStrict.classList.toggle('active', mode === 'Strict');
  modeBalanced.classList.toggle('active', mode === 'Balanced');
  modeOpen.classList.toggle('active', mode === 'Open');
}

modeStrict.onclick = () => {
  api.runtime.sendMessage({ type: 'SET_MODE', mode: 'Strict' });
  setModeUI('Strict');
};
modeBalanced.onclick = () => {
  api.runtime.sendMessage({ type: 'SET_MODE', mode: 'Balanced' });
  setModeUI('Balanced');
};
modeOpen.onclick = () => {
  api.runtime.sendMessage({ type: 'SET_MODE', mode: 'Open' });
  setModeUI('Open');
};

// Render Agent & Autofill State
function renderState(state) {
  if (!state) return;
  const status = state.status || 'idle';

  statusBadge.textContent = status.toUpperCase().replace('_', ' ');
  statusBadge.className = 'status-badge';
  if (status === 'running') statusBadge.classList.add('running');
  else if (status === 'waiting_approval' || status === 'waiting_user_input') statusBadge.classList.add('approval');
  else if (status === 'done') statusBadge.classList.add('done');
  else if (status === 'error' || status === 'stopped') statusBadge.classList.add('error');

  const isRunning = status === 'running';
  btnRun.disabled = isRunning;
  btnStop.disabled = !isRunning;
  btnRunVision.disabled = isRunning;
  btnStopVision.disabled = !isRunning;

  // Domain approval
  if (status === 'waiting_approval' && state.pendingDomainApproval) {
    domainApprovalBox.classList.add('visible');
    domainApprovalDesc.textContent = `Allow Veil Agent on "${state.pendingDomainApproval}"?`;
  } else {
    domainApprovalBox.classList.remove('visible');
  }

  // Autofill Submit Review
  if (status === 'waiting_approval' && state.pendingSubmitAction) {
    submitApprovalBox.classList.add('visible');
    reviewTableBody.innerHTML = '';
    const filled = state.filledFields || [];
    for (const f of filled) {
      const tr = document.createElement('tr');
      const tdLabel = document.createElement('td');
      tdLabel.style.fontWeight = '600';
      tdLabel.textContent = f.label || f.nodeId;

      const tdVal = document.createElement('td');
      tdVal.textContent = f.value;
      tr.appendChild(tdLabel);
      tr.appendChild(tdVal);
      reviewTableBody.appendChild(tr);
    }
  } else {
    submitApprovalBox.classList.remove('visible');
  }

  // Vision Agent Action Approval
  if (status === 'waiting_approval' && state.pendingAction) {
    actionApprovalBox.classList.add('visible');
    actionApprovalDesc.textContent = state.approvalReason || `Confirm action: ${state.pendingAction.action} on ${state.pendingAction.target_id}`;
  } else {
    actionApprovalBox.classList.remove('visible');
  }

  if (state.step !== undefined) telStep.textContent = `${state.step} / 8`;
}

// Log Feed Sync
function appendLog(line) {
  if (logViewer) {
    logViewer.textContent += line + '\n';
    logViewer.scrollTop = logViewer.scrollHeight;
  }
  if (visionLogViewer) {
    visionLogViewer.textContent += line + '\n';
    visionLogViewer.scrollTop = visionLogViewer.scrollHeight;
  }
}

// Autofill Handlers
btnRun.onclick = () => {
  btnRun.disabled = true;
  btnStop.disabled = false;
  submitApprovalBox.classList.remove('visible');
  if (logViewer) logViewer.textContent = 'Starting Autofill...\n';
  api.runtime.sendMessage({ type: 'RUN_AUTOFILL' });
};

btnStop.onclick = () => api.runtime.sendMessage({ type: 'STOP' });
btnApproveSubmit.onclick = () => {
  submitApprovalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'APPROVE_SUBMIT' });
};
btnSkipSubmit.onclick = () => {
  submitApprovalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'SKIP_SUBMIT' });
};
btnApproveDomain.onclick = () => {
  domainApprovalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'APPROVE_DOMAIN' });
};
btnCancelDomain.onclick = () => {
  domainApprovalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'STOP' });
};
btnClearLog.onclick = () => {
  if (logViewer) logViewer.textContent = '';
};

// Vision Agent Handlers
btnRunVision.onclick = () => {
  const goal = (agentGoal?.value || 'Fill form and proceed').trim();
  btnRunVision.disabled = true;
  btnStopVision.disabled = false;
  actionApprovalBox.classList.remove('visible');
  if (visionLogViewer) visionLogViewer.textContent = `Starting Vision Agent with goal: "${goal}"...\n`;
  api.runtime.sendMessage({ type: 'RUN', goal });
};

btnStopVision.onclick = () => api.runtime.sendMessage({ type: 'STOP' });
btnApproveAction.onclick = () => {
  actionApprovalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'APPROVE_ACTION' });
};
btnRejectAction.onclick = () => {
  actionApprovalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'REJECT_ACTION' });
};
btnClearVisionLog.onclick = () => {
  if (visionLogViewer) visionLogViewer.textContent = '';
};

// -------------------------------------------------------------
// "What the Server Sees" Inspection Modal
// -------------------------------------------------------------
function setInspectTab(tab) {
  tabOverlays.classList.toggle('active', tab === 'overlays');
  tabRedacted.classList.toggle('active', tab === 'redacted');
  tabOriginal.classList.toggle('active', tab === 'original');
  tabManifest.classList.toggle('active', tab === 'manifest');

  panelOverlays.style.display = tab === 'overlays' ? 'flex' : 'none';
  panelRedacted.style.display = tab === 'redacted' ? 'flex' : 'none';
  panelOriginal.style.display = tab === 'original' ? 'flex' : 'none';
  panelManifest.style.display = tab === 'manifest' ? 'block' : 'none';
}

tabOverlays.onclick = () => setInspectTab('overlays');
tabRedacted.onclick = () => setInspectTab('redacted');
tabOriginal.onclick = () => setInspectTab('original');
tabManifest.onclick = () => setInspectTab('manifest');

btnOpenInspect.onclick = async () => {
  inspectModal.classList.add('open');
  setInspectTab('overlays');

  const res = await api.runtime.sendMessage({ type: 'GET_INSPECTION_DATA' }).catch(() => null);
  const data = res?.data || res?.view;

  if (!data) {
    overlayCanvas.style.display = 'none';
    overlayPlaceholder.style.display = 'block';
    redactedImg.style.display = 'none';
    redactedPlaceholder.style.display = 'block';
    originalImg.style.display = 'none';
    originalPlaceholder.style.display = 'block';
    manifestContent.textContent = '[]';
    return;
  }

  // Populate Redacted & Original images
  if (data.redactedImage) {
    redactedImg.src = data.redactedImage;
    redactedImg.style.display = 'block';
    redactedPlaceholder.style.display = 'none';
  } else {
    redactedImg.style.display = 'none';
    redactedPlaceholder.style.display = 'block';
  }

  if (data.originalImage) {
    originalImg.src = data.originalImage;
    originalImg.style.display = 'block';
    originalPlaceholder.style.display = 'none';
  } else {
    originalImg.style.display = 'none';
    originalPlaceholder.style.display = 'block';
  }

  // Populate Manifest
  manifestContent.textContent = JSON.stringify(data.manifest || [], null, 2);

  // Render Box Overlays on Canvas
  const baseImg = new Image();
  baseImg.onload = () => {
    overlayCanvas.width = baseImg.naturalWidth || baseImg.width;
    overlayCanvas.height = baseImg.naturalHeight || baseImg.height;
    const ctx = overlayCanvas.getContext('2d');
    ctx.drawImage(baseImg, 0, 0);

    const scaleX = overlayCanvas.width / (data.dom?.viewport?.[0] || overlayCanvas.width);
    const scaleY = overlayCanvas.height / (data.dom?.viewport?.[1] || overlayCanvas.height);

    // 1. Draw Cleared Media (Green dashed)
    const clearedSet = new Set(data.clearedMedia || []);
    for (const node of data.dom?.nodes || []) {
      if (clearedSet.has(node.id) && Array.isArray(node.bbox)) {
        const [nx, ny, nw, nh] = node.bbox;
        const sx = Math.round(nx * scaleX);
        const sy = Math.round(ny * scaleY);
        const sw = Math.round(nw * scaleX);
        const sh = Math.round(nh * scaleY);

        ctx.strokeStyle = '#22c55e';
        ctx.lineWidth = 3;
        ctx.setLineDash([5, 3]);
        ctx.strokeRect(sx, sy, sw, sh);
        ctx.setLineDash([]);
      }
    }

    // 2. Draw Redacted Bounding Boxes
    for (const r of data.manifest || []) {
      const [rx, ry, rw, rh] = r.bbox || [];
      if (rw <= 0 || rh <= 0) continue;

      let color = '#0f172a';
      let tag = r.type || 'REDACTED';

      if (tag.includes('face')) {
        color = '#ef4444';
        tag = 'FACE (UltraFace)';
      } else if (tag.includes('pii_text') || tag.includes('ocr')) {
        color = '#f97316';
        tag = 'OCR PII';
      } else if (tag.includes('pii') || tag.includes('sensitive')) {
        color = '#a855f7';
        tag = 'DOM PII';
      }

      ctx.strokeStyle = color;
      ctx.lineWidth = 2.5;
      ctx.strokeRect(rx, ry, rw, rh);

      ctx.fillStyle = color;
      ctx.fillRect(rx, Math.max(0, ry - 16), Math.min(130, rw + 20), 16);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 9.5px sans-serif';
      ctx.fillText(tag.toUpperCase().slice(0, 16), rx + 4, Math.max(12, ry - 4));
    }

    overlayCanvas.style.display = 'block';
    overlayPlaceholder.style.display = 'none';
  };

  baseImg.src = data.originalImage || data.redactedImage || '';
};

closeModalBtn.onclick = () => inspectModal.classList.remove('open');
inspectModal.onclick = (e) => {
  if (e.target === inspectModal) inspectModal.classList.remove('open');
};

// Export Cryptographic SHA-256 Audit Receipts
btnExportReceipts.onclick = () => {
  api.runtime.sendMessage({ type: 'GET_RECEIPTS' }, (res) => {
    const chain = res?.chain || [];
    if (chain.length === 0) {
      showToast('No audit receipts generated yet.');
      return;
    }
    const blob = new Blob([JSON.stringify(chain, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `veil-audit-receipts-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported ${chain.length} audit receipts!`);
  });
};

// -------------------------------------------------------------
// Vault Controller
// -------------------------------------------------------------
async function loadVaultData() {
  api.runtime.sendMessage({ type: 'GET_VAULT' }, (res) => {
    if (!res || !res.profile) return;
    const profile = res.profile;
    for (const key of VAULT_KEYS) {
      const el = document.getElementById(`v_${key}`);
      if (el) el.value = profile[key] || '';
    }
  });
}

function saveVaultData() {
  const profile = {};
  for (const key of VAULT_KEYS) {
    const el = document.getElementById(`v_${key}`);
    if (el) profile[key] = el.value.trim();
  }

  api.runtime.sendMessage({ type: 'SAVE_VAULT', profile }, (res) => {
    if (res?.ok) {
      showToast('Vault details saved securely');
      appendLog('Saved updated Vault details to local encrypted storage.');
    }
  });
}

btnSaveVault.onclick = saveVaultData;
btnSaveVaultBottom.onclick = saveVaultData;

btnLoadDemo.onclick = () => {
  for (const key of VAULT_KEYS) {
    const el = document.getElementById(`v_${key}`);
    if (el && DEMO_PROFILE[key] !== undefined) {
      el.value = DEMO_PROFILE[key];
    }
  }
  showToast('Sample details loaded. Click Save to apply.');
};

// Runtime Listeners
api.runtime.onMessage.addListener((m) => {
  if (m?.type === 'LOG') {
    appendLog(m.line);
  } else if (m?.type === 'STATE_CHANGED') {
    renderState(m.state);
  } else if (m?.type === 'CLEAR_LOGS') {
    if (logViewer) logViewer.textContent = '';
    if (visionLogViewer) visionLogViewer.textContent = '';
  } else if (m?.type === 'TELEMETRY_UPDATED') {
    const t = m.telemetry;
    if (t) {
      if (t.latency !== undefined) telLatency.textContent = `${Math.round(t.latency)} ms`;
      if (t.bytes !== undefined) telBytes.textContent = `${(t.bytes / 1024).toFixed(1)} KB`;
      if (t.redactions !== undefined) telRedactions.textContent = t.redactions;
      if (t.step !== undefined) telStep.textContent = `${t.step} / 8`;
    }
  }
});

// Startup Sync
api.runtime.sendMessage({ type: 'GET_STATE' }, (res) => {
  if (res?.state) renderState(res.state);
  if (res?.mode) setModeUI(res.mode);
  if (Array.isArray(res?.logs) && res.logs.length > 0) {
    const logStr = res.logs.join('\n') + '\n';
    if (logViewer) {
      logViewer.textContent = logStr;
      logViewer.scrollTop = logViewer.scrollHeight;
    }
    if (visionLogViewer) {
      visionLogViewer.textContent = logStr;
      visionLogViewer.scrollTop = visionLogViewer.scrollHeight;
    }
  }
});

checkServerHealth();
loadVaultData();
