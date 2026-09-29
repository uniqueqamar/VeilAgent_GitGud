// Veil Agent - Floating Draggable In-Page Companion
// Provides an on-screen widget that can be dragged anywhere by its icon or header.
// Encapsulated in Shadow DOM so host page styles never interfere.
// Clean, light-themed, modern, and creative UI.

(() => {
  // Only mount in the top frame
  if (window !== window.top) return;
  if (document.getElementById('veil-agent-host')) return;

  const api = globalThis.browser ?? globalThis.chrome;

  // Create host container
  const host = document.createElement('div');
  host.id = 'veil-agent-host';
  host.style.position = 'fixed';
  host.style.zIndex = '2147483647';
  host.style.pointerEvents = 'none';
  host.style.top = '0';
  host.style.left = '0';
  host.style.width = '100vw';
  host.style.height = '100vh';

  const shadow = host.attachShadow({ mode: 'open' });

  // Stylesheet
  const style = document.createElement('style');
  style.textContent = `
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
    }

    /* Floating Draggable Trigger Icon */
    #veil-trigger {
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 48px;
      height: 48px;
      border-radius: 24px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      box-shadow: 0 4px 20px -2px rgba(15, 23, 42, 0.12), 0 2px 6px -1px rgba(15, 23, 42, 0.06);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: grab;
      user-select: none;
      pointer-events: auto;
      transition: box-shadow 0.2s ease, transform 0.15s ease;
      z-index: 2147483647;
    }
    #veil-trigger:hover {
      box-shadow: 0 8px 26px -4px rgba(15, 23, 42, 0.16);
      transform: translateY(-1px);
    }
    #veil-trigger:active {
      cursor: grabbing;
      transform: scale(0.96);
    }
    #veil-trigger svg {
      width: 22px;
      height: 22px;
      fill: none;
      stroke: #0f172a;
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
      pointer-events: none;
    }
    .trigger-pulse {
      position: absolute;
      top: -2px;
      right: -2px;
      width: 10px;
      height: 10px;
      background: #10b981;
      border-radius: 5px;
      border: 2px solid #ffffff;
    }

    /* Floating Window */
    #veil-panel {
      position: fixed;
      bottom: 84px;
      right: 24px;
      width: 390px;
      max-height: 540px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      box-shadow: 0 16px 40px -8px rgba(15, 23, 42, 0.14), 0 4px 12px -2px rgba(15, 23, 42, 0.06);
      display: none;
      flex-direction: column;
      pointer-events: auto;
      overflow: hidden;
      z-index: 2147483646;
      animation: panelIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes panelIn {
      from { opacity: 0; transform: translateY(8px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    /* Header & Drag Handle */
    .panel-header {
      padding: 12px 16px;
      background: #f8fafc;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: move;
      user-select: none;
    }
    .panel-header:active {
      cursor: grabbing;
    }
    .brand-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .drag-grip {
      width: 6px;
      height: 14px;
      display: grid;
      grid-template-columns: repeat(2, 2px);
      gap: 2px;
      opacity: 0.35;
    }
    .drag-grip span {
      background: #0f172a;
      border-radius: 1px;
    }
    .brand-name {
      font-size: 13.5px;
      font-weight: 700;
      color: #0f172a;
      letter-spacing: -0.2px;
    }
    .status-pill {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 12px;
      background: #f1f5f9;
      color: #64748b;
    }
    .status-pill.running { background: #eff6ff; color: #2563eb; }
    .status-pill.approval { background: #fef3c7; color: #b45309; }
    .status-pill.done { background: #f0fdf4; color: #16a34a; }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .icon-btn {
      width: 26px;
      height: 26px;
      border-radius: 6px;
      border: 0;
      background: transparent;
      color: #64748b;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
      transition: background 0.15s, color 0.15s;
    }
    .icon-btn:hover {
      background: #e2e8f0;
      color: #0f172a;
    }

    /* Tabs */
    .nav-tabs {
      display: flex;
      padding: 8px 16px;
      background: #ffffff;
      border-bottom: 1px solid #f1f5f9;
      gap: 6px;
    }
    .nav-tab {
      flex: 1;
      padding: 6px 10px;
      border-radius: 8px;
      border: 1px solid transparent;
      background: transparent;
      font-size: 12px;
      font-weight: 500;
      color: #64748b;
      cursor: pointer;
      text-align: center;
      transition: all 0.15s;
    }
    .nav-tab.active {
      background: #f1f5f9;
      color: #0f172a;
      font-weight: 600;
      border-color: #e2e8f0;
    }

    /* Content Area */
    .panel-body {
      padding: 14px 16px;
      overflow-y: auto;
      flex: 1;
      background: #ffffff;
    }

    /* Autofill View */
    .action-card {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 12px;
      margin-bottom: 12px;
    }
    .action-text {
      font-size: 12px;
      color: #475569;
      margin-bottom: 10px;
      line-height: 1.4;
    }
    .btn-row {
      display: flex;
      gap: 8px;
    }
    .btn {
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      border: 0;
      transition: all 0.15s;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .btn-dark {
      background: #0f172a;
      color: #ffffff;
      flex: 2;
    }
    .btn-dark:hover { background: #1e293b; }
    .btn-dark:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-light {
      background: #ffffff;
      border: 1px solid #cbd5e1;
      color: #334155;
      flex: 1;
    }
    .btn-light:hover { background: #f8fafc; }
    .btn-success {
      background: #10b981;
      color: #ffffff;
      flex: 2;
    }
    .btn-success:hover { background: #059669; }

    /* Approval Box */
    .approval-box {
      background: #fffbeb;
      border: 1px solid #fde68a;
      border-radius: 10px;
      padding: 12px;
      margin-bottom: 12px;
      display: none;
    }
    .approval-box.visible { display: block; }
    .approval-title {
      font-size: 12.5px;
      font-weight: 700;
      color: #92400e;
      margin-bottom: 6px;
    }
    .approval-desc {
      font-size: 11.5px;
      color: #78350f;
      margin-bottom: 8px;
    }
    .review-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      background: #ffffff;
      border-radius: 6px;
      overflow: hidden;
      border: 1px solid #fde68a;
      margin-bottom: 8px;
    }
    .review-table th, .review-table td {
      padding: 5px 8px;
      text-align: left;
      border-bottom: 1px solid #fef3c7;
    }
    .review-table th { background: #fefce8; color: #78350f; font-weight: 600; }
    .skipped-box {
      font-size: 11px;
      color: #b91c1c;
      margin-bottom: 8px;
      background: #fef2f2;
      border: 1px solid #fecaca;
      border-radius: 6px;
      padding: 6px 8px;
    }

    /* Activity Feed */
    .log-title {
      font-size: 11px;
      font-weight: 700;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      margin-bottom: 6px;
    }
    .log-box {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 8px 10px;
      height: 120px;
      overflow-y: auto;
      font-size: 11px;
      font-family: ui-monospace, Menlo, Consolas, monospace;
      color: #334155;
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* Vault Form */
    .vault-group {
      margin-bottom: 12px;
    }
    .vault-section-title {
      font-size: 11.5px;
      font-weight: 700;
      color: #0f172a;
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .form-row {
      display: flex;
      gap: 8px;
      margin-bottom: 6px;
    }
    .form-col {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .field-label {
      font-size: 10.5px;
      font-weight: 600;
      color: #64748b;
    }
    .input-field {
      padding: 5px 8px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 12px;
      color: #0f172a;
      background: #ffffff;
      outline: none;
    }
    .input-field:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.12);
    }
    .tag-sensitive {
      font-size: 10px;
      color: #ef4444;
      background: #fef2f2;
      border: 1px solid #fee2e2;
      padding: 1px 5px;
      border-radius: 4px;
    }
  `;

  // HTML Template
  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <!-- Draggable Floating Icon -->
    <div id="veil-trigger" title="Veil Agent - Drag anywhere or click to open">
      <svg viewBox="0 0 24 24">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span class="trigger-pulse"></span>
    </div>

    <!-- Draggable Panel -->
    <div id="veil-panel">
      <!-- Drag Header -->
      <div class="panel-header" id="panel-drag-handle">
        <div class="brand-group">
          <div class="drag-grip">
            <span></span><span></span>
            <span></span><span></span>
            <span></span><span></span>
          </div>
          <span class="brand-name">Veil Agent</span>
          <span id="f-status-pill" class="status-pill">Ready</span>
        </div>
        <div class="header-actions">
          <button type="button" id="f-btn-minimize" class="icon-btn" title="Minimize">&minus;</button>
          <button type="button" id="f-btn-close" class="icon-btn" title="Close">&times;</button>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="nav-tabs">
        <button type="button" id="f-tab-autofill" class="nav-tab active">Autofill</button>
        <button type="button" id="f-tab-vault" class="nav-tab">Vault</button>
      </div>

      <!-- Panel Body -->
      <div class="panel-body">
        <!-- AUTOFILL VIEW -->
        <div id="f-view-autofill">
          <div class="action-card">
            <p class="action-text">
              Scans this page, matches form fields against your local Vault keys, and fills them automatically.
            </p>
            <div class="btn-row">
              <button type="button" id="f-btn-run" class="btn btn-dark">Auto-Fill Form</button>
              <button type="button" id="f-btn-stop" class="btn btn-light" disabled>Stop</button>
            </div>
          </div>

          <!-- Submit Approval Box -->
          <div id="f-approval-box" class="approval-box">
            <div class="approval-title">Approval Required Before Submit</div>
            <p class="approval-desc">All matched fields have been filled. Please review and approve form submission.</p>
            
            <table class="review-table">
              <thead>
                <tr><th>Field</th><th>Value</th></tr>
              </thead>
              <tbody id="f-review-tbody"></tbody>
            </table>

            <div id="f-skipped-box" class="skipped-box">
              Sensitive fields (Password / Aadhaar / PAN) were strictly skipped.
            </div>

            <div class="btn-row">
              <button type="button" id="f-btn-approve-submit" class="btn btn-success">Approve & Submit</button>
              <button type="button" id="f-btn-cancel-submit" class="btn btn-light">Keep Filled</button>
            </div>
          </div>

          <!-- Activity Log -->
          <div class="log-title">Activity</div>
          <div id="f-log-box" class="log-box">Ready. Click Auto-Fill Form.</div>
        </div>

        <!-- VAULT VIEW -->
        <div id="f-view-vault" style="display: none;">
          <div style="margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 11.5px; color: #64748b;">Stored locally & encrypted</span>
            <button type="button" id="f-btn-save-vault" class="btn btn-dark" style="padding: 4px 10px; font-size: 11px;">Save Vault</button>
          </div>

          <div class="vault-group">
            <div class="vault-section-title">Personal Details</div>
            <div class="form-row">
              <div class="form-col">
                <span class="field-label">Full Name</span>
                <input type="text" id="fv_FULL_NAME" class="input-field" placeholder="Full Name">
              </div>
              <div class="form-col">
                <span class="field-label">Date of Birth</span>
                <input type="date" id="fv_DOB" class="input-field">
              </div>
            </div>
            <div class="form-row">
              <div class="form-col">
                <span class="field-label">Gender</span>
                <input type="text" id="fv_GENDER" class="input-field" placeholder="Female / Male">
              </div>
              <div class="form-col">
                <span class="field-label">Father's Name</span>
                <input type="text" id="fv_FATHER_NAME" class="input-field" placeholder="Father's Name">
              </div>
            </div>
          </div>

          <div class="vault-group">
            <div class="vault-section-title">Contact</div>
            <div class="form-row">
              <div class="form-col">
                <span class="field-label">Email</span>
                <input type="email" id="fv_EMAIL" class="input-field" placeholder="Email">
              </div>
              <div class="form-col">
                <span class="field-label">Mobile</span>
                <input type="tel" id="fv_MOBILE" class="input-field" placeholder="Mobile">
              </div>
            </div>
          </div>

          <div class="vault-group">
            <div class="vault-section-title">Address</div>
            <div class="form-row">
              <div class="form-col">
                <span class="field-label">Street / House No</span>
                <input type="text" id="fv_ADDRESS_LINE1" class="input-field" placeholder="Address">
              </div>
            </div>
            <div class="form-row">
              <div class="form-col">
                <span class="field-label">City</span>
                <input type="text" id="fv_CITY" class="input-field" placeholder="City">
              </div>
              <div class="form-col">
                <span class="field-label">State</span>
                <input type="text" id="fv_STATE" class="input-field" placeholder="State">
              </div>
              <div class="form-col">
                <span class="field-label">PIN Code</span>
                <input type="text" id="fv_PIN" class="input-field" placeholder="PIN">
              </div>
            </div>
          </div>

          <div class="vault-group">
            <div class="vault-section-title">
              <span>Sensitive (Skipped on forms)</span>
              <span class="tag-sensitive">Protected</span>
            </div>
            <div class="form-row">
              <div class="form-col">
                <span class="field-label">Password</span>
                <input type="password" id="fv_PASSWORD" class="input-field" placeholder="••••••••">
              </div>
              <div class="form-col">
                <span class="field-label">Aadhaar</span>
                <input type="text" id="fv_AADHAAR" class="input-field" placeholder="XXXX XXXX XXXX">
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  shadow.appendChild(style);
  shadow.appendChild(wrapper);
  document.documentElement.appendChild(host);

  // --- Element References ---
  const trigger = shadow.getElementById('veil-trigger');
  const panel = shadow.getElementById('veil-panel');
  const dragHandle = shadow.getElementById('panel-drag-handle');
  const btnClose = shadow.getElementById('f-btn-close');
  const btnMinimize = shadow.getElementById('f-btn-minimize');

  const tabAutofill = shadow.getElementById('f-tab-autofill');
  const tabVault = shadow.getElementById('f-tab-vault');
  const viewAutofill = shadow.getElementById('f-view-autofill');
  const viewVault = shadow.getElementById('f-view-vault');

  const btnRun = shadow.getElementById('f-btn-run');
  const btnStop = shadow.getElementById('f-btn-stop');
  const statusPill = shadow.getElementById('f-status-pill');
  const logBox = shadow.getElementById('f-log-box');

  const approvalBox = shadow.getElementById('f-approval-box');
  const reviewTbody = shadow.getElementById('f-review-tbody');
  const btnApproveSubmit = shadow.getElementById('f-btn-approve-submit');
  const btnCancelSubmit = shadow.getElementById('f-btn-cancel-submit');

  const btnSaveVault = shadow.getElementById('f-btn-save-vault');

  // --- DRAG LOGIC FOR THE TRIGGER ICON ---
  let isDraggingTrigger = false;
  let triggerStartX = 0;
  let triggerStartY = 0;
  let triggerStartLeft = 0;
  let triggerStartTop = 0;
  let hasMovedTrigger = false;

  trigger.addEventListener('pointerdown', (e) => {
    isDraggingTrigger = true;
    hasMovedTrigger = false;
    triggerStartX = e.clientX;
    triggerStartY = e.clientY;

    const rect = trigger.getBoundingClientRect();
    triggerStartLeft = rect.left;
    triggerStartTop = rect.top;

    trigger.setPointerCapture(e.pointerId);
    e.preventDefault();
  });

  trigger.addEventListener('pointermove', (e) => {
    if (!isDraggingTrigger) return;
    const dx = e.clientX - triggerStartX;
    const dy = e.clientY - triggerStartY;

    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
      hasMovedTrigger = true;
    }

    let newLeft = triggerStartLeft + dx;
    let newTop = triggerStartTop + dy;

    // Constrain to viewport boundaries
    newLeft = Math.max(10, Math.min(window.innerWidth - 58, newLeft));
    newTop = Math.max(10, Math.min(window.innerHeight - 58, newTop));

    trigger.style.left = `${newLeft}px`;
    trigger.style.top = `${newTop}px`;
    trigger.style.right = 'auto';
    trigger.style.bottom = 'auto';
  });

  trigger.addEventListener('pointerup', (e) => {
    if (!isDraggingTrigger) return;
    isDraggingTrigger = false;
    try { trigger.releasePointerCapture(e.pointerId); } catch (_) {}

    // If it was just a click and not a drag, toggle panel visibility
    if (!hasMovedTrigger) {
      togglePanel();
    }
  });

  // --- DRAG LOGIC FOR THE EXPANDED PANEL ---
  let isDraggingPanel = false;
  let panelStartX = 0;
  let panelStartY = 0;
  let panelStartLeft = 0;
  let panelStartTop = 0;

  dragHandle.addEventListener('pointerdown', (e) => {
    if (e.target.closest('.icon-btn')) return;
    isDraggingPanel = true;
    panelStartX = e.clientX;
    panelStartY = e.clientY;

    const rect = panel.getBoundingClientRect();
    panelStartLeft = rect.left;
    panelStartTop = rect.top;

    dragHandle.setPointerCapture(e.pointerId);
    e.preventDefault();
  });

  dragHandle.addEventListener('pointermove', (e) => {
    if (!isDraggingPanel) return;
    const dx = e.clientX - panelStartX;
    const dy = e.clientY - panelStartY;

    let newLeft = panelStartLeft + dx;
    let newTop = panelStartTop + dy;

    newLeft = Math.max(10, Math.min(window.innerWidth - panel.offsetWidth - 10, newLeft));
    newTop = Math.max(10, Math.min(window.innerHeight - panel.offsetHeight - 10, newTop));

    panel.style.left = `${newLeft}px`;
    panel.style.top = `${newTop}px`;
    panel.style.right = 'auto';
    panel.style.bottom = 'auto';
  });

  dragHandle.addEventListener('pointerup', (e) => {
    if (!isDraggingPanel) return;
    isDraggingPanel = false;
    try { dragHandle.releasePointerCapture(e.pointerId); } catch (_) {}
  });

  // --- Toggle / Close Panel ---
  function togglePanel() {
    const isVisible = panel.style.display === 'flex';
    if (isVisible) {
      panel.style.display = 'none';
    } else {
      panel.style.display = 'flex';
      // Position panel near the trigger if not yet moved
      if (!panel.style.top && !panel.style.left) {
        const tRect = trigger.getBoundingClientRect();
        if (tRect.top > 560) {
          panel.style.bottom = `${window.innerHeight - tRect.top + 10}px`;
          panel.style.right = `${window.innerWidth - tRect.right}px`;
        } else {
          panel.style.top = `${tRect.bottom + 10}px`;
          panel.style.right = `${window.innerWidth - tRect.right}px`;
        }
      }
      loadVaultToPanel();
    }
  }

  btnClose.onclick = () => { panel.style.display = 'none'; };
  btnMinimize.onclick = () => { panel.style.display = 'none'; };

  // --- Tab Navigation ---
  tabAutofill.onclick = () => {
    tabAutofill.classList.add('active');
    tabVault.classList.remove('active');
    viewAutofill.style.display = 'block';
    viewVault.style.display = 'none';
  };

  tabVault.onclick = () => {
    tabVault.classList.add('active');
    tabAutofill.classList.remove('active');
    viewVault.style.display = 'block';
    viewAutofill.style.display = 'none';
    loadVaultToPanel();
  };

  // --- Logging ---
  function appendLog(line) {
    if (!logBox) return;
    logBox.textContent += line + '\n';
    logBox.scrollTop = logBox.scrollHeight;
  }

  // --- State Rendering ---
  function renderState(state) {
    if (!state) return;
    const status = state.status || 'idle';
    statusPill.className = 'status-pill';

    if (status === 'running') {
      statusPill.classList.add('running');
      statusPill.textContent = 'Filling...';
      btnRun.disabled = true;
      btnStop.disabled = false;
    } else if (status === 'waiting_submit_approval' || (status === 'waiting_approval' && state.pendingSubmitAction)) {
      statusPill.classList.add('approval');
      statusPill.textContent = 'Approval Needed';
      btnRun.disabled = false;
      btnStop.disabled = true;

      // Populate review table
      reviewTbody.innerHTML = '';
      const filled = state.filledFields || [];
      if (filled.length === 0) {
        reviewTbody.innerHTML = '<tr><td colspan="2" style="color:#64748b;">No fields filled</td></tr>';
      } else {
        for (const f of filled) {
          const tr = document.createElement('tr');
          tr.innerHTML = `<strong>${f.label || f.key}</strong><td>${f.masked || f.value}</td>`;
          reviewTbody.appendChild(tr);
        }
      }
      approvalBox.classList.add('visible');
    } else if (status === 'done') {
      statusPill.classList.add('done');
      statusPill.textContent = 'Done';
      btnRun.disabled = false;
      btnStop.disabled = true;
      approvalBox.classList.remove('visible');
    } else {
      statusPill.textContent = 'Ready';
      btnRun.disabled = false;
      btnStop.disabled = true;
      approvalBox.classList.remove('visible');
    }
  }

  // --- Actions ---
  btnRun.onclick = () => {
    logBox.textContent = 'Starting Autofill...\n';
    btnRun.disabled = true;
    btnStop.disabled = false;
    approvalBox.classList.remove('visible');
    api.runtime.sendMessage({ type: 'RUN_AUTOFILL' });
  };

  btnStop.onclick = () => {
    api.runtime.sendMessage({ type: 'STOP' });
  };

  btnApproveSubmit.onclick = () => {
    approvalBox.classList.remove('visible');
    api.runtime.sendMessage({ type: 'APPROVE_SUBMIT' });
  };

  btnCancelSubmit.onclick = () => {
    approvalBox.classList.remove('visible');
    api.runtime.sendMessage({ type: 'SKIP_SUBMIT' });
  };

  // --- Vault Loading & Saving ---
  const VAULT_INPUT_KEYS = ['FULL_NAME', 'DOB', 'GENDER', 'FATHER_NAME', 'EMAIL', 'MOBILE', 'ADDRESS_LINE1', 'CITY', 'STATE', 'PIN', 'PASSWORD', 'AADHAAR'];

  function loadVaultToPanel() {
    api.runtime.sendMessage({ type: 'GET_VAULT' }, (res) => {
      if (!res?.profile) return;
      for (const k of VAULT_INPUT_KEYS) {
        const input = shadow.getElementById(`fv_${k}`);
        if (input) input.value = res.profile[k] || '';
      }
    });
  }

  btnSaveVault.onclick = () => {
    const profile = {};
    for (const k of VAULT_INPUT_KEYS) {
      const input = shadow.getElementById(`fv_${k}`);
      if (input) profile[k] = input.value.trim();
    }
    api.runtime.sendMessage({ type: 'SAVE_VAULT', profile }, (res) => {
      if (res?.ok) {
        btnSaveVault.textContent = 'Saved!';
        setTimeout(() => { btnSaveVault.textContent = 'Save Vault'; }, 1500);
      }
    });
  };

  // --- Message Sync with Background ---
  api.runtime.onMessage.addListener((m) => {
    if (m?.type === 'LOG') {
      appendLog(m.line);
    } else if (m?.type === 'STATE_CHANGED') {
      renderState(m.state);
    } else if (m?.type === 'CLEAR_LOGS') {
      logBox.textContent = '';
    }
  });

  // Initial state fetch
  api.runtime.sendMessage({ type: 'GET_STATE' }, (res) => {
    if (res?.state) renderState(res.state);
    if (Array.isArray(res?.logs) && res.logs.length > 0) {
      logBox.textContent = res.logs.join('\n') + '\n';
      logBox.scrollTop = logBox.scrollHeight;
    }
  });
})();
