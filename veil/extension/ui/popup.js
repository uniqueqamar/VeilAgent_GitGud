const api = globalThis.browser ?? globalThis.chrome;
const sessionStore = api.storage.session ?? api.storage.local;

// DOM Elements
const logEl = document.getElementById('log');
const goalEl = document.getElementById('goal');
const runBtn = document.getElementById('run');
const stopBtn = document.getElementById('stop');
const statusBadge = document.getElementById('status-badge');
const modeBalancedBtn = document.getElementById('mode-balanced');
const modeStrictBtn = document.getElementById('mode-strict');
const modeOpenBtn = document.getElementById('mode-open');

const liveModeBadge = document.getElementById('live-mode-badge');
const liveLatency = document.getElementById('live-latency');
const livePayload = document.getElementById('live-payload');
const liveRedactions = document.getElementById('live-redactions');

const approvalBox = document.getElementById('approval-box');
const approvalDesc = document.getElementById('approval-desc');
const approveBtn = document.getElementById('approve-btn');
const skipBtn = document.getElementById('skip-btn');

const receiptModeBadge = document.getElementById('receipt-mode-badge');
const receiptBytes = document.getElementById('receipt-bytes');
const receiptPii = document.getElementById('receipt-pii');
const receiptHashContainer = document.getElementById('receipt-hash-container');
const exportReceiptsBtn = document.getElementById('export-receipts-btn');
const inspectBtn = document.getElementById('inspect-btn');

const answerCard = document.getElementById('answer-card');
const answerText = document.getElementById('answer-text');
const copyAnswerBtn = document.getElementById('copy-answer-btn');

// Phase 8 DOM Elements
const reviewBox = document.getElementById('review-box');
const reviewTbody = document.getElementById('review-tbody');
const reviewFieldCount = document.getElementById('review-field-count');
const approveReviewBtn = document.getElementById('approve-review-btn');
const skipReviewBtn = document.getElementById('skip-review-btn');

const manualResumeBox = document.getElementById('manual-resume-box');
const manualResumeDesc = document.getElementById('manual-resume-desc');
const resumeTaskBtn = document.getElementById('resume-task-btn');

const askUserBox = document.getElementById('ask-user-box');
const askUserQuestion = document.getElementById('ask-user-question');
const askUserInput = document.getElementById('ask-user-input');
const submitAnswerBtn = document.getElementById('submit-answer-btn');

// Server connection settings
const toggleSettingsHeader = document.getElementById('toggle-settings-header');
const settingsContent = document.getElementById('settings-content');
const serverUrlInput = document.getElementById('server-url-input');
const serverTokenInput = document.getElementById('server-token-input');
const saveSettingsBtn = document.getElementById('save-settings-btn');
const testConnectionBtn = document.getElementById('test-connection-btn');
const settingsStatus = document.getElementById('settings-status');

if (copyAnswerBtn) {
  copyAnswerBtn.onclick = async () => {
    if (answerText?.textContent) {
      await navigator.clipboard.writeText(answerText.textContent);
      copyAnswerBtn.textContent = 'Copied!';
      setTimeout(() => { copyAnswerBtn.textContent = 'Copy Answer'; }, 1500);
    }
  };
}

const visionBackendBadge = document.getElementById('vision-backend-badge');
const visionModelsStatus = document.getElementById('vision-models-status');
const visionLatency = document.getElementById('vision-latency');
const visionClearedCount = document.getElementById('vision-cleared-count');
const visionBlackedCount = document.getElementById('vision-blacked-count');

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
const overlayCanvasPlaceholder = document.getElementById('overlay-canvas-placeholder');
const redactedImg = document.getElementById('redacted-img');
const redactedImgPlaceholder = document.getElementById('redacted-img-placeholder');
const originalImg = document.getElementById('original-img');
const originalImgPlaceholder = document.getElementById('original-img-placeholder');
const manifestContent = document.getElementById('manifest-content');

let currentMode = 'Balanced';

function appendLog(line) {
  logEl.textContent += line + '\n';
  logEl.scrollTop = logEl.scrollHeight;
}

function updateModeUI(mode) {
  currentMode = mode || 'Balanced';
  if (modeStrictBtn) {
    const isStrict = currentMode === 'Strict';
    modeStrictBtn.classList.toggle('active', isStrict);
    modeStrictBtn.setAttribute('aria-checked', String(isStrict));
  }
  if (modeBalancedBtn) {
    const isBalanced = currentMode === 'Balanced';
    modeBalancedBtn.classList.toggle('active', isBalanced);
    modeBalancedBtn.setAttribute('aria-checked', String(isBalanced));
  }
  if (modeOpenBtn) {
    const isOpen = currentMode === 'Open';
    modeOpenBtn.classList.toggle('active', isOpen);
    modeOpenBtn.setAttribute('aria-checked', String(isOpen));
  }
  if (liveModeBadge) {
    liveModeBadge.textContent = currentMode;
  }
}

if (modeBalancedBtn) {
  modeBalancedBtn.onclick = async () => {
    updateModeUI('Balanced');
    await api.storage.local.set({ agentMode: 'Balanced' });
    appendLog('Mode set to Balanced (Redacted visual screenshots + tokens).');
  };
}

if (modeStrictBtn) {
  modeStrictBtn.onclick = async () => {
    updateModeUI('Strict');
    await api.storage.local.set({ agentMode: 'Strict' });
    appendLog('Mode set to Strict (Tokens only, zero screenshots).');
  };
}

if (modeOpenBtn) {
  modeOpenBtn.onclick = async () => {
    updateModeUI('Open');
    await api.storage.local.set({ agentMode: 'Open' });
    appendLog('Mode set to Open (Full resolution & extended DOM text, all tokenized).');
  };
}

function renderTelemetry(telemetry) {
  if (!telemetry) return;
  if (liveLatency) liveLatency.textContent = telemetry.latency !== undefined ? `${telemetry.latency} ms` : '—';
  if (livePayload) livePayload.textContent = telemetry.bytes !== undefined ? `${telemetry.bytes} B` : '0 B';
  if (liveRedactions) liveRedactions.textContent = String(telemetry.redactions ?? 0);
  if (liveModeBadge && telemetry.mode) liveModeBadge.textContent = telemetry.mode;
}

function renderState(state) {
  if (!state) return;
  const isRunning = state.status === 'running';
  const isWaitingApproval = state.status === 'waiting_approval';

  statusBadge.className = 'status-badge ' + (state.status || 'stopped');
  statusBadge.textContent = state.status ? state.status.replace('_', ' ') : 'Ready';

  runBtn.disabled = isRunning || isWaitingApproval;
  stopBtn.disabled = !isRunning && !isWaitingApproval;
  if (isRunning || isWaitingApproval) {
    stopBtn.classList.add('danger');
  } else {
    stopBtn.classList.remove('danger');
  }

  if (isWaitingApproval && (state.pendingAction || state.pendingDomainApproval)) {
    if (state.pendingDomainApproval) {
      approvalDesc.textContent = `New domain: "${state.pendingDomainApproval}". Allow agent access?`;
      approveBtn.textContent = 'Allow Domain';
      skipBtn.style.display = 'none';
    } else {
      const desc = state.rawAction?.reason || `${state.pendingAction.action} on ${state.pendingAction.target_id ?? 'element'}`;
      approvalDesc.textContent = `Action: ${state.pendingAction.action.toUpperCase()} (${desc})`;
      approveBtn.textContent = 'Approve';
      skipBtn.style.display = 'block';
    }
    approvalBox.classList.add('visible');
  } else {
    approvalBox.classList.remove('visible');
  }

  // Task 7: Render answer display using textContent ONLY (never innerHTML)
  if (state.status === 'answered' && state.answer) {
    if (answerCard && answerText) {
      answerCard.style.display = 'block';
      answerText.textContent = state.answer;
    }
  } else if (!state.answer) {
    if (answerCard) answerCard.style.display = 'none';
  }

  // Phase 8: Review-Before-Submit Table (Task 7)
  const isWaitingReview = state.status === 'waiting_review' && Array.isArray(state.reviewTable);
  if (isWaitingReview && reviewBox && reviewTbody) {
    reviewBox.style.display = 'block';
    if (reviewFieldCount) reviewFieldCount.textContent = `${state.reviewTable.length} fields`;
    while (reviewTbody.firstChild) {
      reviewTbody.removeChild(reviewTbody.firstChild);
    }

    for (const item of state.reviewTable) {
      const tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--line)';

      const tdLabel = document.createElement('td');
      tdLabel.style.padding = '5px 8px';
      tdLabel.style.fontWeight = '600';
      tdLabel.textContent = item.label || item.nodeId;

      const tdVal = document.createElement('td');
      tdVal.style.padding = '5px 8px';
      const valSpan = document.createElement('span');
      valSpan.textContent = item.masked || item.value;
      tdVal.appendChild(valSpan);

      if (item.value && item.masked && item.value !== item.masked) {
        const toggleBtn = document.createElement('button');
        toggleBtn.type = 'button';
        toggleBtn.textContent = 'Reveal';
        toggleBtn.style.marginLeft = '6px';
        toggleBtn.style.padding = '1px 5px';
        toggleBtn.style.fontSize = '10px';
        toggleBtn.style.borderRadius = '3px';
        toggleBtn.style.border = '1px solid #cbd5e1';
        toggleBtn.style.background = '#f8fafc';
        toggleBtn.style.cursor = 'pointer';
        let revealed = false;
        toggleBtn.onclick = () => {
          revealed = !revealed;
          valSpan.textContent = revealed ? item.value : item.masked;
          toggleBtn.textContent = revealed ? 'Hide' : 'Reveal';
        };
        tdVal.appendChild(toggleBtn);
      }

      const tdSrc = document.createElement('td');
      tdSrc.style.padding = '5px 8px';
      tdSrc.style.color = 'var(--text-muted)';
      tdSrc.textContent = item.source || 'Vault';

      tr.appendChild(tdLabel);
      tr.appendChild(tdVal);
      tr.appendChild(tdSrc);
      reviewTbody.appendChild(tr);
    }
  } else if (reviewBox) {
    reviewBox.style.display = 'none';
  }

  // Phase 8: Manual Stop Conditions (Task 4)
  const isWaitingUser = state.status === 'waiting_user';
  if (isWaitingUser && manualResumeBox && manualResumeDesc) {
    manualResumeBox.style.display = 'block';
    manualResumeDesc.textContent = state.stopMessage || 'Manual action required. Please complete it and click Resume.';
  } else if (manualResumeBox) {
    manualResumeBox.style.display = 'none';
  }

  // Phase 8: Clarification Needed (Task 2 & 9)
  const isWaitingInput = state.status === 'waiting_user_input';
  if (isWaitingInput && askUserBox && askUserQuestion) {
    askUserBox.style.display = 'block';
    askUserQuestion.textContent = state.userQuestion || state.question || 'Please provide information.';
  } else if (askUserBox) {
    askUserBox.style.display = 'none';
  }
}

function renderReceipt(receipt) {
  if (!receipt) {
    receiptModeBadge.textContent = 'None';
    receiptBytes.textContent = '0 B';
    receiptPii.textContent = 'None';
    receiptHashContainer.textContent = 'SHA-256 Hash: —';
    return;
  }
  receiptModeBadge.textContent = receipt.mode || 'Unknown';
  receiptBytes.textContent = `${receipt.bytes || 0} bytes`;

  const counts = receipt.counts || {};
  const piiSummary = Object.entries(counts)
    .map(([k, v]) => `${k}:${v}`)
    .join(', ') || '0 detected';
  receiptPii.textContent = piiSummary;

  const hash = receipt.hash || '';
  receiptHashContainer.textContent = hash ? `Hash: ${hash.slice(0, 16)}...${hash.slice(-8)}` : 'SHA-256 Hash: —';
  receiptHashContainer.title = hash;

  if (receipt.vision) {
    if (visionBackendBadge) visionBackendBadge.textContent = (receipt.vision.backend || 'WASM SIMD').toUpperCase();
    if (visionLatency) visionLatency.textContent = `${receipt.vision.totalVisionMs || 0} ms`;
    if (visionClearedCount) visionClearedCount.textContent = receipt.vision.elementsCleared || 0;
    if (visionBlackedCount) visionBlackedCount.textContent = receipt.vision.elementsBlackedOut || 0;
  }
}

async function loadFromStorage() {
  const { agent_state: state, agent_logs: logs, latest_receipt: receipt } =
    await sessionStore.get(['agent_state', 'agent_logs', 'latest_receipt']);

  const { agentMode = 'Balanced' } = await api.storage.local.get('agentMode');
  updateModeUI(agentMode);

  const { server_url, server_token } = await api.storage.local.get(['server_url', 'server_token']);
  if (serverUrlInput && server_url) serverUrlInput.value = server_url;
  if (serverTokenInput && server_token) serverTokenInput.value = server_token;

  if (state?.goal && !goalEl.value.trim()) {
    goalEl.value = state.goal;
  }
  if (Array.isArray(logs) && logs.length > 0) {
    logEl.textContent = logs.join('\n') + '\n';
    logEl.scrollTop = logEl.scrollHeight;
  } else {
    logEl.textContent = 'Ready.\n';
  }
  renderState(state);
  renderReceipt(receipt);

  const storedTelemetry = await sessionStore.get('last_step_telemetry');
  if (storedTelemetry?.last_step_telemetry) {
    renderTelemetry(storedTelemetry.last_step_telemetry);
  }
}

runBtn.onclick = () => {
  const goal = goalEl.value.trim();
  if (!goal) return;
  logEl.textContent = 'Starting...\n';
  runBtn.disabled = true;
  stopBtn.disabled = false;
  api.runtime.sendMessage({ type: 'RUN', goal });
};

stopBtn.onclick = () => {
  api.runtime.sendMessage({ type: 'STOP' });
};

approveBtn.onclick = async () => {
  approvalBox.classList.remove('visible');
  const { agent_state: state } = await sessionStore.get('agent_state');
  if (state?.pendingDomainApproval) {
    api.runtime.sendMessage({ type: 'APPROVE_DOMAIN' });
  } else {
    api.runtime.sendMessage({ type: 'APPROVE_ACTION' });
  }
};

skipBtn.onclick = () => {
  approvalBox.classList.remove('visible');
  api.runtime.sendMessage({ type: 'SKIP_ACTION' });
};

// Phase 8 Button Handlers
if (approveReviewBtn) {
  approveReviewBtn.onclick = () => {
    if (reviewBox) reviewBox.style.display = 'none';
    api.runtime.sendMessage({ type: 'APPROVE_REVIEW' });
  };
}

if (skipReviewBtn) {
  skipReviewBtn.onclick = () => {
    if (reviewBox) reviewBox.style.display = 'none';
    api.runtime.sendMessage({ type: 'SKIP_ACTION' });
  };
}

if (resumeTaskBtn) {
  resumeTaskBtn.onclick = () => {
    if (manualResumeBox) manualResumeBox.style.display = 'none';
    api.runtime.sendMessage({ type: 'RESUME_TASK' });
  };
}

if (submitAnswerBtn) {
  submitAnswerBtn.onclick = () => {
    const val = askUserInput?.value || '';
    if (askUserBox) askUserBox.style.display = 'none';
    api.runtime.sendMessage({ type: 'ANSWER_USER_QUESTION', answer: val });
  };
}

// Tamper-Evident Receipts Export
exportReceiptsBtn.onclick = async () => {
  const { receipt_chain: chain, latest_receipt: latest } =
    await sessionStore.get(['receipt_chain', 'latest_receipt']);

  const receiptsArray = Array.isArray(chain) ? chain : (latest ? [latest] : []);
  const headHash = receiptsArray.length > 0
    ? receiptsArray[receiptsArray.length - 1].hash
    : '0000000000000000000000000000000000000000000000000000000000000000';

  const exportPayload = {
    type: 'tamper-evident-audit-chain',
    head: headHash,
    count: receiptsArray.length,
    generated_at: new Date().toISOString(),
    receipts: receiptsArray
  };

  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `veil-tamper-evident-receipts-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  appendLog(`Exported ${receiptsArray.length} tamper-evident receipt(s) (head: ${headHash.slice(0, 10)}...).`);
};

// Privacy Report HTML Export (Task 8)
const exportReportBtn = document.getElementById('export-report-btn');
if (exportReportBtn) {
  exportReportBtn.onclick = async () => {
    const { receipt_chain: chain, latest_receipt: latest, agent_state: state } =
      await sessionStore.get(['receipt_chain', 'latest_receipt', 'agent_state']);

    const receiptsArray = Array.isArray(chain) ? chain : (latest ? [latest] : []);
    const generator = globalThis.VeilPrivacyReport;
    if (!generator || typeof generator.generatePrivacyReportHtml !== 'function') {
      appendLog('Privacy report generator not loaded.');
      return;
    }

    const htmlContent = generator.generatePrivacyReportHtml({
      receipts: receiptsArray,
      goal: state?.goal || goalEl?.value || 'Automated session',
      mode: currentMode
    });

    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `veil-privacy-report-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    appendLog(`Exported self-contained Privacy Report HTML (${receiptsArray.length} receipts, DPDP mapping).`);
  };
}

// "What the server sees" Inspection View (Task 9)
inspectBtn.onclick = async () => {
  inspectModal.classList.add('open');
  const response = await api.runtime.sendMessage({ type: 'GET_SERVER_VIEW' }).catch(() => null);
  const view = response?.view;

  // Render overlays
  if (view && (view.redactedImage || view.originalImage)) {
    const imgSrc = view.originalImage || view.redactedImage;
    const img = new Image();
    img.onload = () => {
      overlayCanvas.width = img.naturalWidth || img.width;
      overlayCanvas.height = img.naturalHeight || img.height;
      const ctx = overlayCanvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      // 1. Draw cleared media boxes (green dashed)
      const clearedSet = new Set(view.clearedMedia || []);
      const domNodes = view.dom?.nodes || [];
      const scaleX = overlayCanvas.width / (view.dom?.viewport?.[0] || overlayCanvas.width);
      const scaleY = overlayCanvas.height / (view.dom?.viewport?.[1] || overlayCanvas.height);

      for (const node of domNodes) {
        if (clearedSet.has(node.id) && Array.isArray(node.bbox)) {
          const [nx, ny, nw, nh] = node.bbox;
          const sx = Math.round(nx * scaleX);
          const sy = Math.round(ny * scaleY);
          const sw = Math.round(nw * scaleX);
          const sh = Math.round(nh * scaleY);

          ctx.strokeStyle = '#22c55e';
          ctx.lineWidth = 3;
          ctx.setLineDash([6, 4]);
          ctx.strokeRect(sx, sy, sw, sh);
          ctx.setLineDash([]);

          ctx.fillStyle = '#22c55e';
          ctx.font = 'bold 11px system-ui, sans-serif';
          ctx.fillRect(sx, Math.max(0, sy - 18), 110, 18);
          ctx.fillStyle = '#ffffff';
          ctx.fillText('MEDIA CLEARED', sx + 4, Math.max(13, sy - 5));
        }
      }

      // 2. Draw redacted boxes (faces, OCR, DOM PII, media blacked out)
      const manifest = view.manifest || [];
      for (const item of manifest) {
        const [x, y, w, h] = item.bbox;
        let strokeColor = '#0f172a';
        let fillColor = 'rgba(15, 23, 42, 0.4)';
        let label = item.type;

        if (item.type === 'face') {
          strokeColor = '#ef4444';
          fillColor = 'rgba(239, 68, 68, 0.35)';
          label = 'FACE REDACTED';
        } else if (item.type === 'pii_ocr_text') {
          strokeColor = '#f97316';
          fillColor = 'rgba(249, 115, 22, 0.35)';
          label = 'OCR PII TEXT';
        } else if (item.type?.startsWith('pii_')) {
          strokeColor = '#a855f7';
          fillColor = 'rgba(168, 85, 247, 0.35)';
          label = 'DOM PII';
        } else if (item.type?.startsWith('media_')) {
          strokeColor = '#0f172a';
          fillColor = 'rgba(0, 0, 0, 0.6)';
          label = 'MEDIA SOLID BLACK';
        }

        ctx.fillStyle = fillColor;
        ctx.fillRect(x, y, w, h);
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 2;
        ctx.strokeRect(x, y, w, h);

        const labelWidth = Math.max(70, label.length * 7 + 8);
        ctx.fillStyle = strokeColor;
        ctx.fillRect(x, Math.max(0, y - 16), labelWidth, 16);
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 10px system-ui, sans-serif';
        ctx.fillText(label, x + 4, Math.max(12, y - 4));
      }

      overlayCanvas.style.display = 'block';
      overlayCanvasPlaceholder.style.display = 'none';
    };
    img.src = imgSrc;
  } else {
    overlayCanvas.style.display = 'none';
    overlayCanvasPlaceholder.style.display = 'block';
  }

  if (view && view.redactedImage) {
    redactedImg.src = view.redactedImage;
    redactedImg.style.display = 'block';
    redactedImgPlaceholder.style.display = 'none';
  } else {
    redactedImg.src = '';
    redactedImg.style.display = 'none';
    redactedImgPlaceholder.style.display = 'block';
  }

  if (view && view.originalImage) {
    originalImg.src = view.originalImage;
    originalImg.style.display = 'block';
    originalImgPlaceholder.style.display = 'none';
  } else {
    originalImg.src = '';
    originalImg.style.display = 'none';
    originalImgPlaceholder.style.display = 'block';
  }

  if (view && Array.isArray(view.manifest) && view.manifest.length > 0) {
    manifestContent.textContent = JSON.stringify(view.manifest, null, 2);
  } else {
    manifestContent.textContent = 'No redactions applied in this capture step.';
  }
};

function closeInspectModal() {
  inspectModal.classList.remove('open');
  redactedImg.src = '';
  originalImg.src = '';
  if (overlayCanvas) {
    const ctx = overlayCanvas.getContext('2d');
    ctx?.clearRect(0, 0, overlayCanvas.width, overlayCanvas.height);
  }
  // Invariant & Task 6: Clear original screenshot from volatile memory immediately when closed
  api.runtime.sendMessage({ type: 'CLEAR_SERVER_VIEW' }).catch(() => {});
}

closeModalBtn.onclick = closeInspectModal;

inspectModal.onclick = (e) => {
  if (e.target === inspectModal) {
    closeInspectModal();
  }
};

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && inspectModal.classList.contains('open')) {
    closeInspectModal();
  }
});

// Modal Tabs
function setActiveInspectTab(activeTab, activePanel) {
  [tabOverlays, tabRedacted, tabOriginal, tabManifest].forEach((t) => t.classList.remove('active'));
  [panelOverlays, panelRedacted, panelOriginal, panelManifest].forEach((p) => (p.style.display = 'none'));
  activeTab.classList.add('active');
  activePanel.style.display = activePanel === panelManifest ? 'block' : 'flex';
}

tabOverlays.onclick = () => setActiveInspectTab(tabOverlays, panelOverlays);
tabRedacted.onclick = () => setActiveInspectTab(tabRedacted, panelRedacted);
tabOriginal.onclick = () => setActiveInspectTab(tabOriginal, panelOriginal);
tabManifest.onclick = () => setActiveInspectTab(tabManifest, panelManifest);

// Window unload: ensure in-memory raw image is purged
window.addEventListener('beforeunload', () => {
  api.runtime.sendMessage({ type: 'CLEAR_SERVER_VIEW' }).catch(() => {});
});

// Real-time runtime message listeners
api.runtime.onMessage.addListener((m) => {
  if (m?.type === 'LOG') {
    appendLog(m.line);
  } else if (m?.type === 'STATE_CHANGED') {
    renderState(m.state);
  } else if (m?.type === 'TELEMETRY_UPDATED') {
    renderTelemetry(m.telemetry);
  } else if (m?.type === 'CLEAR_LOGS') {
    logEl.textContent = '';
  }
});

// Storage sync
if (api.storage?.onChanged) {
  api.storage.onChanged.addListener((changes, area) => {
    if (area === 'session' || area === 'local') {
      if (changes.agent_logs?.newValue) {
        logEl.textContent = changes.agent_logs.newValue.join('\n') + '\n';
        logEl.scrollTop = logEl.scrollHeight;
      }
      if (changes.agent_state?.newValue) {
        renderState(changes.agent_state.newValue);
      }
      if (changes.latest_receipt?.newValue) {
        renderReceipt(changes.latest_receipt.newValue);
      }
      if (changes.last_step_telemetry?.newValue) {
        renderTelemetry(changes.last_step_telemetry.newValue);
      }
      if (changes.agentMode?.newValue) {
        updateModeUI(changes.agentMode.newValue);
      }
    }
  });
}

// Backend Connection Settings Handlers
if (toggleSettingsHeader && settingsContent) {
  toggleSettingsHeader.onclick = () => {
    const isHidden = settingsContent.style.display === 'none';
    settingsContent.style.display = isHidden ? 'block' : 'none';
  };
}

if (saveSettingsBtn) {
  saveSettingsBtn.onclick = async () => {
    const url = serverUrlInput?.value.trim() || 'http://127.0.0.1:8000';
    const token = serverTokenInput?.value.trim() || 'veil-shared-secret-token';
    await api.storage.local.set({ server_url: url, server_token: token });
    if (settingsStatus) {
      settingsStatus.style.display = 'block';
      settingsStatus.style.color = 'var(--signal)';
      settingsStatus.textContent = 'Settings saved!';
      setTimeout(() => { settingsStatus.style.display = 'none'; }, 3000);
    }
  };
}

if (testConnectionBtn) {
  testConnectionBtn.onclick = async () => {
    const url = (serverUrlInput?.value.trim() || 'http://127.0.0.1:8000').replace(/\/+$/, '');
    const token = serverTokenInput?.value.trim() || 'veil-shared-secret-token';
    if (settingsStatus) {
      settingsStatus.style.display = 'block';
      settingsStatus.style.color = 'var(--primary)';
      settingsStatus.textContent = 'Testing connection & auth...';
    }
    try {
      const res = await fetch(url + '/auth/verify', {
        headers: { 'X-Veil-Token': token }
      });
      if (res.ok) {
        if (settingsStatus) {
          settingsStatus.style.color = 'var(--signal)';
          settingsStatus.textContent = 'Connected & Authenticated (HTTP 200 OK)';
        }
      } else if (res.status === 401) {
        if (settingsStatus) {
          settingsStatus.style.color = 'var(--danger)';
          settingsStatus.textContent = 'Auth Failed: Token does not match server VEIL_SERVER_TOKEN (HTTP 401). Restart python server.';
        }
      } else {
        const hRes = await fetch(url + '/health');
        if (hRes.ok) {
          if (settingsStatus) {
            settingsStatus.style.color = 'var(--signal)';
            settingsStatus.textContent = 'Connected (HTTP 200 OK)';
          }
        } else {
          if (settingsStatus) {
            settingsStatus.style.color = 'var(--danger)';
            settingsStatus.textContent = `Server responded: HTTP ${res.status}`;
          }
        }
      }
    } catch (e) {
      if (settingsStatus) {
        settingsStatus.style.color = 'var(--danger)';
        settingsStatus.textContent = `Connection failed: ${e.message}`;
      }
    }
  };
}

// Initial render
loadFromStorage();
