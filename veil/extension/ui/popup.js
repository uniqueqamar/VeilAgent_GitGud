// UI Controller for Veil Agent Popup
// Manages: 1. Form Autofill Dashboard & Submit Approval
//          2. Comprehensive Vault Profile Editor (One-Time Setup)

const api = globalThis.browser ?? globalThis.chrome;

// DOM Elements - Navigation
const tabAutofill = document.getElementById('tab-autofill');
const tabVault = document.getElementById('tab-vault');
const viewAutofill = document.getElementById('view-autofill');
const viewVault = document.getElementById('view-vault');

// DOM Elements - Status & Controls
const statusBadge = document.getElementById('status-badge');
const btnRun = document.getElementById('btn-run');
const btnStop = document.getElementById('btn-stop');
const logViewer = document.getElementById('log-viewer');
const btnClearLog = document.getElementById('btn-clear-log');

// DOM Elements - Submit Approval Box
const submitApprovalBox = document.getElementById('submit-approval-box');
const reviewTableBody = document.getElementById('review-table-body');
const skippedChipsList = document.getElementById('skipped-chips-list');
const btnApproveSubmit = document.getElementById('btn-approve-submit');
const btnSkipSubmit = document.getElementById('btn-skip-submit');

// DOM Elements - Domain Approval Box
const domainApprovalBox = document.getElementById('domain-approval-box');
const domainApprovalDesc = document.getElementById('domain-approval-desc');
const btnApproveDomain = document.getElementById('btn-approve-domain');
const btnCancelDomain = document.getElementById('btn-cancel-domain');

// DOM Elements - Vault Form
const vaultForm = document.getElementById('vault-form');
const btnSaveVault = document.getElementById('btn-save-vault');
const btnSaveVaultBottom = document.getElementById('btn-save-vault-bottom');
const btnLoadDemo = document.getElementById('btn-load-demo');
const btnCopyAddress = document.getElementById('btn-copy-address');
const toastEl = document.getElementById('toast');

const VAULT_KEYS = [
  'FULL_NAME', 'FIRST_NAME', 'LAST_NAME', 'DOB', 'GENDER', 'FATHER_NAME', 'MOTHER_NAME',
  'NATIONALITY', 'CATEGORY', 'BLOOD_GROUP', 'MARITAL_STATUS',
  'EMAIL', 'MOBILE', 'ALT_MOBILE', 'WORK_EMAIL', 'MOBILE_CC',
  'ADDRESS_LINE1', 'ADDRESS_LINE2', 'CITY', 'DISTRICT', 'STATE', 'PIN', 'COUNTRY',
  'PERMANENT_ADDRESS_LINE1', 'PERMANENT_CITY', 'PERMANENT_STATE', 'PERMANENT_PIN', 'PERMANENT_COUNTRY',
  'DEGREE', 'MAJOR', 'COLLEGE', 'GRADUATION_YEAR', 'CGPA', 'SCHOOL_12TH', 'SCHOOL_10TH',
  'JOB_TITLE', 'COMPANY', 'EXPERIENCE_YEARS', 'ANNUAL_SALARY', 'LINKEDIN_URL', 'GITHUB_URL', 'PORTFOLIO_URL',
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
  BLOOD_GROUP: 'O+',
  MARITAL_STATUS: 'Single',
  EMAIL: 'tanishachoudhary090405@gmail.com',
  MOBILE: '9876543210',
  ALT_MOBILE: '9876543211',
  WORK_EMAIL: 'tanisha@work.com',
  MOBILE_CC: '+91',
  ADDRESS_LINE1: 'Flat 402, Green Glen Heights, Outer Ring Road',
  ADDRESS_LINE2: 'Near Bellandur Junction',
  CITY: 'Bengaluru',
  DISTRICT: 'Bengaluru Urban',
  STATE: 'Karnataka',
  PIN: '560103',
  COUNTRY: 'India',
  PERMANENT_ADDRESS_LINE1: 'Flat 402, Green Glen Heights, Outer Ring Road',
  PERMANENT_CITY: 'Bengaluru',
  PERMANENT_STATE: 'Karnataka',
  PERMANENT_PIN: '560103',
  PERMANENT_COUNTRY: 'India',
  DEGREE: 'Bachelor of Technology (B.Tech)',
  MAJOR: 'Computer Science and Engineering',
  COLLEGE: 'National Institute of Technology',
  GRADUATION_YEAR: '2026',
  CGPA: '9.2',
  SCHOOL_12TH: 'Delhi Public School',
  SCHOOL_10TH: 'Delhi Public School',
  JOB_TITLE: 'Software Engineer',
  COMPANY: 'Tech Innovators Inc',
  EXPERIENCE_YEARS: '1',
  ANNUAL_SALARY: '900000',
  LINKEDIN_URL: 'https://linkedin.com/in/tanisha-choudhary',
  GITHUB_URL: 'https://github.com/tanisha-choudhary',
  PORTFOLIO_URL: 'https://tanisha.dev',
  PASSWORD: 'DemoPassword#2026',
  AADHAAR: '3675 9834 6012',
  PAN: 'ABCDE1234F',
  PASSPORT: 'P1234567'
};

// --- Toast helper ---
function showToast(msg) {
  if (!toastEl) return;
  toastEl.textContent = msg;
  toastEl.style.display = 'block';
  setTimeout(() => {
    toastEl.style.display = 'none';
  }, 2200);
}

// --- Navigation Tabs ---
tabAutofill.onclick = () => {
  tabAutofill.classList.add('active');
  tabVault.classList.remove('active');
  viewAutofill.classList.add('active');
  viewVault.classList.remove('active');
};

tabVault.onclick = () => {
  tabVault.classList.add('active');
  tabAutofill.classList.remove('active');
  viewVault.classList.add('active');
  viewAutofill.classList.remove('active');
  loadVaultData();
};

// --- Logging ---
function appendLog(line) {
  if (!logViewer) return;
  logViewer.textContent += line + '\n';
  logViewer.scrollTop = logViewer.scrollHeight;
}

btnClearLog.onclick = () => {
  if (logViewer) logViewer.textContent = '';
};

// --- State Rendering ---
function renderState(state) {
  if (!state) return;

  const status = state.status || 'idle';
  statusBadge.className = 'badge';

  if (status === 'running') {
    statusBadge.classList.add('badge-running');
    statusBadge.textContent = 'Filling...';
    btnRun.disabled = true;
    btnStop.disabled = false;
  } else if (status === 'waiting_submit_approval') {
    statusBadge.classList.add('badge-approval');
    statusBadge.textContent = 'Approval Required';
    btnRun.disabled = false;
    btnStop.disabled = true;
  } else if (status === 'done') {
    statusBadge.classList.add('badge-done');
    statusBadge.textContent = 'Completed';
    btnRun.disabled = false;
    btnStop.disabled = true;
  } else if (status === 'error') {
    statusBadge.classList.add('badge-error');
    statusBadge.textContent = 'Error';
    btnRun.disabled = false;
    btnStop.disabled = true;
  } else {
    statusBadge.classList.add('badge-idle');
    statusBadge.textContent = 'Ready';
    btnRun.disabled = false;
    btnStop.disabled = true;
  }

  // STEP 4: SUBMIT -> ASKS FOR APPROVAL
  if (status === 'waiting_submit_approval') {
    submitApprovalBox.classList.add('visible');

    // Populate review table
    reviewTableBody.innerHTML = '';
    const filled = state.filledFields || [];
    if (filled.length === 0) {
      reviewTableBody.innerHTML = '<tr><td colspan="2" style="color:var(--text-muted);">No fields filled.</td></tr>';
    } else {
      for (const f of filled) {
        const tr = document.createElement('tr');
        const tdLabel = document.createElement('td');
        tdLabel.style.fontWeight = '600';
        tdLabel.textContent = f.label || f.key;

        const tdVal = document.createElement('td');
        tdVal.textContent = f.masked || f.value;

        tr.appendChild(tdLabel);
        tr.appendChild(tdVal);
        reviewTableBody.appendChild(tr);
      }
    }

    // Populate skipped sensitive chips
    skippedChipsList.innerHTML = '';
    const skipped = state.skippedFields || [];
    if (skipped.length === 0) {
      skippedChipsList.innerHTML = '<span style="font-size:11px; color:var(--text-muted);">None detected</span>';
    } else {
      for (const s of skipped) {
        const chip = document.createElement('span');
        chip.className = 'skipped-chip';
        chip.textContent = `${s.label} (${s.type})`;
        skippedChipsList.appendChild(chip);
      }
    }
  } else {
    submitApprovalBox.classList.remove('visible');
  }

  // Domain approval check
  if (status === 'waiting_approval' && state.pendingDomainApproval) {
    domainApprovalBox.classList.add('visible');
    domainApprovalDesc.textContent = `Allow Veil Agent to autofill on "${state.pendingDomainApproval}"?`;
  } else {
    domainApprovalBox.classList.remove('visible');
  }
}

// --- Autofill Action Handlers ---
btnRun.onclick = () => {
  btnRun.disabled = true;
  btnStop.disabled = false;
  submitApprovalBox.classList.remove('visible');
  if (logViewer) logViewer.textContent = 'Starting Autofill...\n';
  api.runtime.sendMessage({ type: 'RUN_AUTOFILL' });
};

btnStop.onclick = () => {
  api.runtime.sendMessage({ type: 'STOP' });
};

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

// --- STEP 1: ONE-TIME SETUP VAULT CONTROLLER ---
async function loadVaultData() {
  api.runtime.sendMessage({ type: 'GET_VAULT' }, (res) => {
    if (!res || !res.profile) return;
    const profile = res.profile;

    for (const key of VAULT_KEYS) {
      const el = document.getElementById(`v_${key}`);
      if (el) {
        el.value = profile[key] || '';
      }
    }
  });
}

function saveVaultData() {
  const profile = {};
  for (const key of VAULT_KEYS) {
    const el = document.getElementById(`v_${key}`);
    if (el) {
      profile[key] = el.value.trim();
    }
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

btnCopyAddress.onclick = () => {
  const street = document.getElementById('v_ADDRESS_LINE1')?.value || '';
  const city = document.getElementById('v_CITY')?.value || '';
  const state = document.getElementById('v_STATE')?.value || '';
  const pin = document.getElementById('v_PIN')?.value || '';
  const country = document.getElementById('v_COUNTRY')?.value || '';

  const pStreet = document.getElementById('v_PERMANENT_ADDRESS_LINE1');
  const pCity = document.getElementById('v_PERMANENT_CITY');
  const pState = document.getElementById('v_PERMANENT_STATE');
  const pPin = document.getElementById('v_PERMANENT_PIN');
  const pCountry = document.getElementById('v_PERMANENT_COUNTRY');

  if (pStreet) pStreet.value = street;
  if (pCity) pCity.value = city;
  if (pState) pState.value = state;
  if (pPin) pPin.value = pin;
  if (pCountry) pCountry.value = country;

  showToast('Copied current address to permanent address.');
};

// --- Storage & Message Sync ---
api.runtime.onMessage.addListener((m) => {
  if (m?.type === 'LOG') {
    appendLog(m.line);
  } else if (m?.type === 'STATE_CHANGED') {
    renderState(m.state);
  } else if (m?.type === 'CLEAR_LOGS') {
    if (logViewer) logViewer.textContent = '';
  }
});

// Initial startup
api.runtime.sendMessage({ type: 'GET_STATE' }, (res) => {
  if (res?.state) renderState(res.state);
  if (Array.isArray(res?.logs) && res.logs.length > 0) {
    if (logViewer) {
      logViewer.textContent = res.logs.join('\n') + '\n';
      logViewer.scrollTop = logViewer.scrollHeight;
    }
  }
});

loadVaultData();
