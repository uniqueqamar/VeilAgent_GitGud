// Self-Contained Privacy Report HTML Generator for Veil Agent (Task 8)
// Exports an escaped, standalone HTML audit report with informational DPDP mapping.
// Disclaims clearly that DPDP mapping is for technical transparency and NOT legal advice.

(() => {
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Generates a self-contained HTML privacy report document.
   * @param {Object} sessionData - { receipts, goal, mode, startTime, endTime }
   * @returns {string} - Full HTML string
   */
  function generatePrivacyReportHtml(sessionData = {}) {
    const receipts = sessionData.receipts || [];
    const goal = sessionData.goal || 'General automation task';
    const mode = sessionData.mode || (receipts.length > 0 ? receipts[0].mode : 'Balanced');
    const timestamp = new Date().toISOString();
    const headHash = receipts.length > 0 ? receipts[receipts.length - 1].hash : '0'.repeat(64);

    let totalBytes = 0;
    let totalRedactions = 0;
    const piiSummary = {};

    for (const r of receipts) {
      totalBytes += r.bytes || 0;
      totalRedactions += r.redactionCount || 0;
      if (r.counts) {
        for (const [k, v] of Object.entries(r.counts)) {
          piiSummary[k] = (piiSummary[k] || 0) + v;
        }
      }
    }

    const piiListHtml = Object.keys(piiSummary).length > 0
      ? Object.entries(piiSummary).map(([k, v]) => `<li><strong>${escapeHtml(k)}:</strong> ${escapeHtml(v)} occurrences redacted</li>`).join('')
      : '<li>No direct PII identifiers encountered</li>';

    const receiptRowsHtml = receipts.map((r, idx) => `
      <tr>
        <td>${idx + 1}</td>
        <td>${escapeHtml(r.time ? r.time.slice(11, 19) : '—')}</td>
        <td><span class="badge ${escapeHtml((r.mode || '').toLowerCase())}">${escapeHtml(r.mode || 'Strict')}</span></td>
        <td>${escapeHtml(r.bytes || 0)} B</td>
        <td>${escapeHtml(r.redactionCount || 0)}</td>
        <td><code>${escapeHtml((r.hash || '').slice(0, 16))}...</code></td>
        <td><code>${escapeHtml((r.hashPrev || '').slice(0, 16))}...</code></td>
      </tr>
    `).join('');

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Veil Agent - Privacy & Security Audit Report</title>
<style>
  :root {
    --ink: #0f172a;
    --muted: #475569;
    --paper: #f8fafc;
    --card: #ffffff;
    --line: #e2e8f0;
    --primary: #0284c7;
    --signal: #0d9488;
    --danger: #e11d48;
    --warning: #b45309;
    --warning-bg: #fefce8;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 30px 20px;
    background: var(--paper);
    color: var(--ink);
    font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .container {
    max-width: 860px;
    margin: 0 auto;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 32px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
  }
  h1 { font-size: 24px; margin: 0 0 6px; letter-spacing: -0.5px; }
  h2 { font-size: 17px; margin: 24px 0 12px; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
  p { margin: 0 0 12px; color: var(--muted); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0 24px; }
  .stat-card { background: var(--paper); padding: 14px; border-radius: 8px; border: 1px solid var(--line); }
  .stat-card .label { font-size: 11.5px; text-transform: uppercase; font-weight: 700; color: var(--muted); }
  .stat-card .val { font-size: 20px; font-weight: 700; color: var(--ink); margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
  th, td { padding: 8px 10px; border: 1px solid var(--line); text-align: left; }
  th { background: #f1f5f9; font-weight: 600; color: var(--ink); }
  code { font-family: ui-monospace, Menlo, Monaco, monospace; font-size: 11.5px; background: #f1f5f9; padding: 2px 4px; border-radius: 4px; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge.balanced { background: #e0f2fe; color: #0369a1; }
  .badge.strict { background: #f1f5f9; color: #475569; }
  .badge.open { background: #fef3c7; color: #92400e; }
  .disclaimer-box {
    margin-top: 30px;
    padding: 14px;
    border-radius: 8px;
    background: var(--warning-bg);
    border: 1px solid #fef08a;
    font-size: 12px;
    color: var(--warning);
    line-height: 1.5;
  }
</style>
</head>
<body>
<div class="container">
  <h1>Veil Agent &mdash; Privacy Audit & DPDP Compliance Report</h1>
  <p>Cryptographically verifiable, tamper-evident audit record generated automatically on-device.</p>

  <div class="grid">
    <div class="stat-card">
      <div class="label">Operating Mode</div>
      <div class="val">${escapeHtml(mode)}</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Steps</div>
      <div class="val">${escapeHtml(receipts.length)}</div>
    </div>
    <div class="stat-card">
      <div class="label">Network Egress</div>
      <div class="val">${(totalBytes / 1024).toFixed(1)} KB</div>
    </div>
    <div class="stat-card">
      <div class="label">Redacted Boxes</div>
      <div class="val">${escapeHtml(totalRedactions)}</div>
    </div>
  </div>

  <h2>Session Summary</h2>
  <p><strong>Goal:</strong> ${escapeHtml(goal)}</p>
  <p><strong>Generated At:</strong> ${escapeHtml(timestamp)}</p>
  <p><strong>Chain Head Hash:</strong> <code>${escapeHtml(headHash)}</code></p>

  <h2>Redacted PII Summary</h2>
  <ul>
    ${piiListHtml}
  </ul>

  <h2>Tamper-Evident SHA-256 Step Receipt Chain</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Time</th>
        <th>Mode</th>
        <th>Payload</th>
        <th>Redactions</th>
        <th>Receipt Hash</th>
        <th>Previous Hash</th>
      </tr>
    </thead>
    <tbody>
      ${receiptRowsHtml || '<tr><td colspan="7">No receipts generated.</td></tr>'}
    </tbody>
  </table>

  <h2>Informational DPDP Act (2023) Architecture Mapping</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 22%;">DPDP Section</th>
        <th style="width: 38%;">Regulatory Principle</th>
        <th style="width: 40%;">Veil Agent Implementation Guarantee</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Section 4</strong></td>
        <td>Grounds for Processing &amp; Purpose Limitation</td>
        <td>Data minimization strictly enforced; high-sensitivity fields (Aadhaar, PAN, Bank) are blocked on low-stakes forms; unknown fields trigger <code>ask_user</code>.</td>
      </tr>
      <tr>
        <td><strong>Section 6</strong></td>
        <td>Consent Architecture &amp; Specific Notice</td>
        <td>Consent, terms, and declaration checkboxes are NEVER automated; mandatory Review-Before-Submit table with click-to-reveal values is confirmed by the user.</td>
      </tr>
      <tr>
        <td><strong>Section 8</strong></td>
        <td>Obligations of Data Fiduciary / Processor</td>
        <td>Client-side WebCrypto encryption (PBKDF2 + AES-GCM-256); visual redaction with 4px expansion &amp; pixel sampling self-check; single network egress gatekeeper.</td>
      </tr>
      <tr>
        <td><strong>Section 9</strong></td>
        <td>Protection of Personal Data</td>
        <td>Plain HTTP blocked; identity values reside strictly in browser vault and are never sent to planner servers; images stay in volatile memory only.</td>
      </tr>
      <tr>
        <td><strong>Section 12</strong></td>
        <td>Transparency &amp; Auditability</td>
        <td>Tamper-evident SHA-256 receipt chain verifiable via independent script (<code>verify_receipt.js</code>).</td>
      </tr>
    </tbody>
  </table>

  <div class="disclaimer-box">
    <strong>Legal Notice &amp; Compliance Disclaimer:</strong><br>
    This privacy report and regulatory mapping to the Digital Personal Data Protection Act (DPDP), 2023 is provided strictly for technical transparency, architectural documentation, and auditing verification purposes. It does <strong>NOT</strong> constitute formal legal advice or statutory compliance certification.
  </div>
</div>
</body>
</html>`;
  }

  const VeilPrivacyReport = {
    generatePrivacyReportHtml,
    escapeHtml
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilPrivacyReport = VeilPrivacyReport;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilPrivacyReport;
  }
})();
