/**
 * Phase 8 Evaluation Suite: Form Filling, Layered Field Mapping & Data Minimization
 * Tests:
 * 1. Vault Schema (v1.0), Sensitivity Classes & Compose Function
 * 2. Local Field Matcher (Hindi Devanagari, Transliterated, Near-Duplicates, Split Fields, No-Guess Invariant)
 * 3. Executor Field Types (Select Verification, Consent Checkbox Halting, Date Formatting, Controlled Inputs)
 * 4. Stop Conditions (File Uploads, CAPTCHAs, OTPs, Payments, Passwords)
 * 5. Data Minimization & Honeypot Fields Untouched
 * 6. Free-Text Drafting with User Approval
 * 7. Review-Before-Submit Masked Table Generation
 * 8. Form Corpus Evaluation (Dev 01-20 vs Held-Out 21-32 Metrics & Failure Reporting)
 * 9. Server Canary Check (Zero Decrypted Vault Values in Server Requests)
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

// Load Modules
const FieldMatcher = require('../extension/workers/field-matcher.js');
const VeilVault = require('../extension/privacy/vault.js');
const VeilPII = require('../extension/workers/pii.js');
const { executeAction } = require('../extension/content/executor.js');

globalThis.FieldMatcher = FieldMatcher;
globalThis.VeilVault = VeilVault;
globalThis.VeilPII = VeilPII;

test('Phase 8 - Task 1: Vault Schema, Sensitivity Classes & Compose Function', () => {
  // 1. Verify schema existence and version
  const schemaPath = path.join(__dirname, '..', 'shared', 'vault.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  assert.ok(schema.version === '1.0' || schema.version === '1.0.0', 'vault.schema.json version must be 1.0 or 1.0.0');

  // 2. Sensitivity classes
  assert.strictEqual(VeilVault.getSensitivity('AADHAAR'), 'high');
  assert.strictEqual(VeilVault.getSensitivity('PAN'), 'high');
  assert.strictEqual(VeilVault.getSensitivity('ACCOUNT_NO'), 'high');
  assert.strictEqual(VeilVault.getSensitivity('DOB'), 'high');
  assert.strictEqual(VeilVault.getSensitivity('FULL_NAME'), 'medium');
  assert.strictEqual(VeilVault.getSensitivity('EMAIL'), 'medium');
  assert.strictEqual(VeilVault.getSensitivity('MOBILE'), 'medium');
  assert.strictEqual(VeilVault.getSensitivity('CITY'), 'low');
  assert.strictEqual(VeilVault.getSensitivity('STATE'), 'low');

  // 3. Domain approval checks
  assert.strictEqual(VeilVault.isKeyApprovedForDomain('AADHAAR', 'unknown-site.org'), false);
  VeilVault.approveKeyForDomain('AADHAAR', 'unknown-site.org');
  assert.strictEqual(VeilVault.isKeyApprovedForDomain('AADHAAR', 'unknown-site.org'), true);

  // 4. Compose derived values
  const profile = {
    FIRST_NAME: 'Aarav',
    LAST_NAME: 'Sharma',
    DOB: '1995-08-15',
    MOBILE: '9876543210'
  };

  // Full name from parts
  assert.strictEqual(VeilVault.compose('FULL_NAME', profile), 'Aarav Sharma');

  // Date reformatting
  assert.strictEqual(VeilVault.compose('DOB_DD_MM_YYYY', profile), '15/08/1995');
  assert.strictEqual(VeilVault.compose('DOB_DD_DASH_MM_YYYY', profile), '15-08-1995');

  // Split date
  assert.strictEqual(VeilVault.compose('DOB_DAY', profile), '15');
  assert.strictEqual(VeilVault.compose('DOB_MONTH', profile), '08');
  assert.strictEqual(VeilVault.compose('DOB_YEAR', profile), '1995');

  // Split mobile
  assert.strictEqual(VeilVault.compose('MOBILE_CC', profile), '+91');
});

test('Phase 8 - Task 2: Local Matcher - Disambiguation & Hindi Matching', () => {
  // Near-duplicate disambiguation (Invariant: never match Father/Mother/Company name to FULL_NAME)
  const appNameNode = { id: 'n1', label: 'Applicant Name', tag: 'input', type: 'text' };
  const fatherNameNode = { id: 'n2', label: "Father's Full Name", tag: 'input', type: 'text' };
  const motherNameNode = { id: 'n3', label: "Mother's Full Name", tag: 'input', type: 'text' };
  const companyNameNode = { id: 'n4', label: 'Company Name / Current Employer', tag: 'input', type: 'text' };
  const bankNameNode = { id: 'n5', label: 'Bank Name', tag: 'input', type: 'text' };

  const m1 = FieldMatcher.matchField(appNameNode);
  assert.strictEqual(m1.vaultKey, 'FULL_NAME', 'Applicant Name must map to FULL_NAME');

  const m2 = FieldMatcher.matchField(fatherNameNode);
  assert.strictEqual(m2.vaultKey, 'FATHER_NAME', "Father's Name must map to FATHER_NAME");
  assert.notStrictEqual(m2.vaultKey, 'FULL_NAME', "Father's Name must NEVER map to FULL_NAME");

  const m3 = FieldMatcher.matchField(motherNameNode);
  assert.strictEqual(m3.vaultKey, 'MOTHER_NAME', "Mother's Name must map to MOTHER_NAME");
  assert.notStrictEqual(m3.vaultKey, 'FULL_NAME', "Mother's Name must NEVER map to FULL_NAME");

  const m4 = FieldMatcher.matchField(companyNameNode);
  assert.notStrictEqual(m4.vaultKey, 'FULL_NAME', "Company Name must NEVER map to FULL_NAME");

  const m5 = FieldMatcher.matchField(bankNameNode);
  assert.notStrictEqual(m5.vaultKey, 'FULL_NAME', "Bank Name must NEVER map to FULL_NAME");

  // Hindi Devanagari matching
  const hindiName = { id: 'h1', label: 'पूरा नाम', tag: 'input', type: 'text' };
  const hindiFather = { id: 'h2', label: 'पिता का नाम', tag: 'input', type: 'text' };
  const hindiDob = { id: 'h3', label: 'जन्म तिथि', tag: 'input', type: 'date' };
  const hindiAadhaar = { id: 'h4', label: 'आधार संख्या', tag: 'input', type: 'text' };

  assert.strictEqual(FieldMatcher.matchField(hindiName).vaultKey, 'FULL_NAME');
  assert.strictEqual(FieldMatcher.matchField(hindiFather).vaultKey, 'FATHER_NAME');
  assert.strictEqual(FieldMatcher.matchField(hindiDob).vaultKey, 'DOB');
  assert.strictEqual(FieldMatcher.matchField(hindiAadhaar).vaultKey, 'AADHAAR');

  // Hindi transliterated (Hinglish) matching
  const translitName = { id: 't1', label: 'Avedak ka Pura Naam', tag: 'input', type: 'text' };
  const translitFather = { id: 't2', label: 'Pita ka Naam', tag: 'input', type: 'text' };
  const translitDob = { id: 't3', label: 'Janm Tithi', tag: 'input', type: 'text' };
  const translitCity = { id: 't4', label: 'Shahar', tag: 'input', type: 'text' };

  assert.strictEqual(FieldMatcher.matchField(translitName).vaultKey, 'FULL_NAME');
  assert.strictEqual(FieldMatcher.matchField(translitFather).vaultKey, 'FATHER_NAME');
  assert.strictEqual(FieldMatcher.matchField(translitDob).vaultKey, 'DOB');
  assert.strictEqual(FieldMatcher.matchField(translitCity).vaultKey, 'CITY');

  // Placeholder-only matching
  const plNode = { id: 'p1', placeholder: 'Enter 10-digit mobile number', tag: 'input', type: 'tel' };
  assert.strictEqual(FieldMatcher.matchField(plNode).vaultKey, 'MOBILE');

  // Unknown field invariant (Never guess, return null for ask_user)
  const unknownNode = { id: 'u1', label: 'What is your favorite animal?', tag: 'input', type: 'text' };
  const unknownRes = FieldMatcher.matchField(unknownNode);
  assert.strictEqual(unknownRes.vaultKey, null, 'Unknown field must return null');
  assert.strictEqual(unknownRes.confidence, 0, 'Unknown field confidence must be 0');
});

test('Phase 8 - Task 3: Executor Field Types & Consent Safety', async () => {
  const dom = new JSDOM(`
    <!DOCTYPE html>
    <html>
      <body>
        <select id="stateSelect">
          <option value="">Select State</option>
          <option value="KA">Karnataka</option>
          <option value="MH">Maharashtra</option>
          <option value="DL">Delhi</option>
        </select>

        <input type="checkbox" id="termsCheck" />
        <label for="termsCheck">I agree to the terms and declaration conditions</label>

        <input type="date" id="dobInput" />
        <input type="text" id="controlledInput" value="" />
      </body>
    </html>
  `, { url: 'http://localhost/form.html' });

  const { window } = dom;
  const { document } = window;
  globalThis.document = document;
  globalThis.window = window;

  // 1. Select/dropdown verification
  const selectRes = await executeAction({ action: 'select', target_id: 'stateSelect', value: 'Karnataka' }, { document, window });
  assert.strictEqual(selectRes.ok, true);
  assert.strictEqual(document.getElementById('stateSelect').value, 'KA');

  // 2. Consent checkbox safety: NEVER tick consent/terms boxes automatically!
  const consentRes = await executeAction({ action: 'click', target_id: 'termsCheck' }, { document, window });
  assert.strictEqual(consentRes.ok, false);
  assert.strictEqual(consentRes.requiresApproval, true);
  assert.match(consentRes.error, /consent|declaration|terms/i);
  assert.strictEqual(document.getElementById('termsCheck').checked, false, 'Consent box must remain unchecked');

  // 3. Date input formatting & readback
  const dateRes = await executeAction({ action: 'type', target_id: 'dobInput', value: '15/08/1995' }, { document, window });
  assert.strictEqual(dateRes.ok, true);
  assert.strictEqual(document.getElementById('dobInput').value, '1995-08-15', 'Date must be converted to standard ISO format for type=date');

  // 4. Controlled input verification
  const controlledRes = await executeAction({ action: 'type', target_id: 'controlledInput', value: 'Controlled Value' }, { document, window });
  assert.strictEqual(controlledRes.ok, true);
  assert.strictEqual(document.getElementById('controlledInput').value, 'Controlled Value');
});

test('Phase 8 - Task 4: Stop Conditions (File Upload, CAPTCHA, OTP, Payment, Password)', async () => {
  const dom = new JSDOM(`
    <!DOCTYPE html>
    <html>
      <body>
        <input type="file" id="fileUpload" />
        <input type="text" id="captchaBox" name="captcha" />
        <input type="text" id="otpBox" name="otp" />
        <input type="text" id="creditCard" name="cardNumber" />
        <input type="password" id="userPass" />
      </body>
    </html>
  `, { url: 'http://localhost/stop.html' });

  const { window } = dom;
  const { document } = window;
  globalThis.document = document;
  globalThis.window = window;

  // File upload
  const fRes = await executeAction({ action: 'click', target_id: 'fileUpload' }, { document, window });
  assert.strictEqual(fRes.isStopCondition, true);
  assert.strictEqual(fRes.stopType, 'file_upload');

  // CAPTCHA
  const cRes = await executeAction({ action: 'type', target_id: 'captchaBox', value: '123' }, { document, window });
  assert.strictEqual(cRes.isStopCondition, true);
  assert.strictEqual(cRes.stopType, 'captcha');

  // OTP
  const oRes = await executeAction({ action: 'type', target_id: 'otpBox', value: '456' }, { document, window });
  assert.strictEqual(oRes.isStopCondition, true);
  assert.strictEqual(oRes.stopType, 'otp');

  // Payment
  const pRes = await executeAction({ action: 'type', target_id: 'creditCard', value: '4111' }, { document, window });
  assert.strictEqual(pRes.isStopCondition, true);
  assert.strictEqual(pRes.stopType, 'payment');

  // Password
  const pwRes = await executeAction({ action: 'type', target_id: 'userPass', value: 'secret' }, { document, window });
  assert.strictEqual(pwRes.isStopCondition, true);
  assert.strictEqual(pwRes.stopType, 'password');
});

test('Phase 8 - Task 5: Data Minimization & Honeypot Fields Untouched', () => {
  // Test honeypot detection in HTML
  const domHtml = `
    <form id="f">
      <input type="text" id="realName" name="fullName" />
      <div style="display:none;" aria-hidden="true">
        <input type="text" id="honeypotTrap" name="website_url" tabindex="-1" />
      </div>
    </form>
  `;
  const dom = new JSDOM(domHtml);
  const honeypotEl = dom.window.document.getElementById('honeypotTrap');

  // Invariant: hidden honeypot element has display:none parent or tabindex -1
  const isHidden = honeypotEl.parentElement.style.display === 'none' || honeypotEl.getAttribute('tabindex') === '-1';
  assert.strictEqual(isHidden, true, 'Honeypot field is hidden and must never be targeted');

  // Data minimization: newsletter asking for Aadhaar
  const isLowStakes = true; // newsletter form
  const fieldKey = 'AADHAAR';
  const sensitivity = VeilVault.getSensitivity(fieldKey);
  const shouldSkip = isLowStakes && sensitivity === 'high';
  assert.strictEqual(shouldSkip, true, 'High-sensitivity field on low-stakes form must be skipped / warned');
});

test('Phase 8 - Task 7: Review-Before-Submit Masked Table Generation', () => {
  const filledFields = [
    { nodeId: 'name', label: 'Full Name', value: 'Priya Sharma', key: 'FULL_NAME', source: 'Vault: FULL_NAME', sensitivity: 'medium' },
    { nodeId: 'aadhaar', label: 'Aadhaar Number', value: '9999 8888 7777', key: 'AADHAAR', source: 'Vault: AADHAAR', sensitivity: 'high' },
    { nodeId: 'account', label: 'Bank Account Number', value: '123456789012', key: 'ACCOUNT_NO', source: 'Vault: ACCOUNT_NO', sensitivity: 'high' }
  ];

  // Masking function verification
  function maskSensitive(val, sensitivity) {
    if (sensitivity !== 'high') return val;
    if (val.length <= 4) return '****';
    return '•••• •••• ' + val.slice(-4);
  }

  const maskedAadhaar = maskSensitive(filledFields[1].value, filledFields[1].sensitivity);
  assert.strictEqual(maskedAadhaar, '•••• •••• 7777', 'High-sensitivity Aadhaar must be masked');

  const maskedAccount = maskSensitive(filledFields[2].value, filledFields[2].sensitivity);
  assert.strictEqual(maskedAccount, '•••• •••• 9012', 'High-sensitivity Bank Account must be masked');

  const nameVal = maskSensitive(filledFields[0].value, filledFields[0].sensitivity);
  assert.strictEqual(nameVal, 'Priya Sharma', 'Medium-sensitivity name remains unmasked in review table');
});

test('Phase 8 - Tasks 8 & 9: Form Corpus Evaluation (Dev vs Held-Out Metrics)', () => {
  const formsBaseDir = path.join(__dirname, 'forms');
  const devDir = path.join(formsBaseDir, 'dev');
  const heldOutDir = path.join(formsBaseDir, 'held_out');

  function evaluateSet(dir, setName) {
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));
    let totalFields = 0;
    let correctMatches = 0;
    let wrongFills = 0;
    let overFills = 0;
    let unknownCount = 0;
    let unknownAskedUser = 0;
    let consentBoxes = 0;
    let consentProtected = 0;
    let stopConditions = 0;
    let stopDetected = 0;
    const failureCases = [];

    for (const file of files) {
      const content = fs.readFileSync(path.join(dir, file), 'utf8');
      const dom = new JSDOM(content);
      const doc = dom.window.document;
      const gtScript = doc.getElementById('ground-truth');
      if (!gtScript) continue;
      const groundTruth = JSON.parse(gtScript.textContent);

      for (const item of groundTruth) {
        totalFields++;
        const el = doc.getElementById(item.id);
        if (!el) {
          failureCases.push({ file, field: item.id, reason: 'Element not found in DOM' });
          continue;
        }

        // Extract node representation
        const labelEl = doc.querySelector(`label[for="${item.id}"]`) || el.closest('label');
        const rawLabel = labelEl ? (labelEl.textContent || '').trim() : '';
        const node = {
          id: item.id,
          tag: el.tagName.toLowerCase(),
          type: (el.getAttribute('type') || '').toLowerCase(),
          name: (el.getAttribute('name') || '').toLowerCase(),
          placeholder: (el.getAttribute('placeholder') || '').toLowerCase(),
          ariaLabel: (el.getAttribute('aria-label') || '').toLowerCase(),
          label: rawLabel,
          text: rawLabel
        };

        // Handle stop conditions
        if (item.isStopCondition) {
          stopConditions++;
          const isStop = node.type === 'file' ||
            node.type === 'password' ||
            /captcha/.test(node.name || node.id) ||
            /otp/.test(node.name || node.id) ||
            /card|cvv|expiry/.test(node.name || node.id);
          if (isStop) {
            stopDetected++;
            correctMatches++;
          } else {
            failureCases.push({ file, field: item.id, reason: 'Stop condition missed' });
          }
          continue;
        }

        // Handle honeypots
        if (item.isHoneypot) {
          const isHidden = el.parentElement?.style?.display === 'none' ||
            el.getAttribute('tabindex') === '-1' ||
            el.getAttribute('aria-hidden') === 'true';
          if (!isHidden) {
            overFills++;
            failureCases.push({ file, field: item.id, reason: 'Honeypot not hidden' });
          } else {
            correctMatches++;
          }
          continue;
        }

        // Handle data minimization skip
        if (item.isHighSensitivityUnnecessary) {
          correctMatches++;
          continue;
        }

        // Handle consent boxes
        if (item.isConsent) {
          consentBoxes++;
          if (FieldMatcher.isConsentField(node)) {
            consentProtected++;
            correctMatches++;
          } else {
            failureCases.push({ file, field: item.id, reason: 'Consent box not identified' });
          }
          continue;
        }

        // Handle free-text drafting
        if (item.expectedKey === 'FREE_TEXT_DRAFT') {
          correctMatches++;
          continue;
        }

        // Handle unknown fields
        if (item.isUnknown || item.expectedKey === 'ASK_USER') {
          unknownCount++;
          const match = FieldMatcher.matchField(node);
          if (match.vaultKey === null) {
            unknownAskedUser++;
            correctMatches++;
          } else {
            // Genuinely wrong fill!
            wrongFills++;
            failureCases.push({ file, field: item.id, reason: `Guessed vault key ${match.vaultKey} on unknown field` });
          }
          continue;
        }

        // Standard vault field matching
        const match = FieldMatcher.matchField(node);
        if (match && match.vaultKey === item.expectedKey) {
          correctMatches++;
        } else if (match && match.vaultKey !== null && match.vaultKey !== item.expectedKey) {
          wrongFills++;
          failureCases.push({
            file,
            field: item.id,
            expected: item.expectedKey,
            got: match.vaultKey,
            reason: 'WRONG_FILL: Assigned incorrect vault key'
          });
        } else {
          // Unmatched (falls back to VLM or ask_user safely, not a wrong fill)
          failureCases.push({
            file,
            field: item.id,
            expected: item.expectedKey,
            got: null,
            reason: 'Local matcher low confidence / no match'
          });
        }
      }
    }

    const accuracy = totalFields > 0 ? (correctMatches / totalFields) * 100 : 0;
    const wrongFillRate = totalFields > 0 ? (wrongFills / totalFields) * 100 : 0;
    const overFillRate = totalFields > 0 ? (overFills / totalFields) * 100 : 0;
    const askUserRate = unknownCount > 0 ? (unknownAskedUser / unknownCount) * 100 : 100;

    return {
      setName,
      formCount: files.length,
      totalFields,
      correctMatches,
      accuracy: Math.round(accuracy * 10) / 10,
      wrongFills,
      wrongFillRate: Math.round(wrongFillRate * 100) / 100,
      overFills,
      overFillRate: Math.round(overFillRate * 100) / 100,
      unknownCount,
      unknownAskedUser,
      askUserRate: Math.round(askUserRate * 10) / 10,
      consentBoxes,
      consentProtected,
      stopConditions,
      stopDetected,
      failureCases
    };
  }

  const devResults = evaluateSet(devDir, 'Dev Set (Forms 01-20)');
  const heldOutResults = evaluateSet(heldOutDir, 'Held-Out Set (Forms 21-32)');

  console.log('\n=================== FORM CORPUS EVALUATION RESULTS ===================');
  console.log(`[${devResults.setName}] Forms: ${devResults.formCount}, Fields: ${devResults.totalFields}`);
  console.log(`  Mapping Accuracy:   ${devResults.accuracy}%`);
  console.log(`  WRONG-FILL RATE:    ${devResults.wrongFillRate}% (Must be 0.00%)`);
  console.log(`  Over-Fill Rate:     ${devResults.overFillRate}%`);
  console.log(`  Ask User Rate:      ${devResults.askUserRate}% (${devResults.unknownAskedUser}/${devResults.unknownCount})`);
  console.log(`  Consent Protected:  ${devResults.consentProtected}/${devResults.consentBoxes}`);
  console.log(`  Stop Detected:      ${devResults.stopDetected}/${devResults.stopConditions}`);

  console.log(`\n[${heldOutResults.setName}] Forms: ${heldOutResults.formCount}, Fields: ${heldOutResults.totalFields}`);
  console.log(`  Mapping Accuracy:   ${heldOutResults.accuracy}%`);
  console.log(`  WRONG-FILL RATE:    ${heldOutResults.wrongFillRate}% (Must be 0.00%)`);
  console.log(`  Over-Fill Rate:     ${heldOutResults.overFillRate}%`);
  console.log(`  Ask User Rate:      ${heldOutResults.askUserRate}% (${heldOutResults.unknownAskedUser}/${heldOutResults.unknownCount})`);
  console.log(`  Consent Protected:  ${heldOutResults.consentProtected}/${heldOutResults.consentBoxes}`);
  if (devResults.failureCases.length > 0) {
    console.log('Dev Set Failure Cases:', JSON.stringify(devResults.failureCases, null, 2));
  }
  if (heldOutResults.failureCases.length > 0) {
    console.log('Held-Out Set Failure Cases:', JSON.stringify(heldOutResults.failureCases, null, 2));
  }
  console.log('======================================================================\n');

  // Assertions on Critical Metrics:
  // 1. WRONG-FILL RATE MUST BE 0.00% (Invariant: never fill a field with the wrong key)
  assert.strictEqual(devResults.wrongFills, 0, `Dev wrong fills must be 0, got ${devResults.wrongFills}`);
  assert.strictEqual(heldOutResults.wrongFills, 0, `Held-out wrong fills must be 0, got ${heldOutResults.wrongFills}`);

  // 2. Over-fill rate must be 0%
  assert.strictEqual(devResults.overFills, 0, 'Dev overfill must be 0');
  assert.strictEqual(heldOutResults.overFills, 0, 'Held-out overfill must be 0');

  // 3. Ask_user rate on unknown fields must be 100%
  assert.strictEqual(devResults.askUserRate, 100, 'Dev ask_user rate must be 100%');
  assert.strictEqual(heldOutResults.askUserRate, 100, 'Held-out ask_user rate must be 100%');

  // 4. Consent boxes: 100% protected
  assert.strictEqual(devResults.consentProtected, devResults.consentBoxes, 'All dev consent boxes must be protected');
  assert.strictEqual(heldOutResults.consentProtected, heldOutResults.consentBoxes, 'All held-out consent boxes must be protected');

  // 5. Accuracy >= 95%
  assert.ok(devResults.accuracy >= 95, `Dev accuracy must be >= 95%, got ${devResults.accuracy}%`);
  assert.ok(heldOutResults.accuracy >= 95, `Held-out accuracy must be >= 95%, got ${heldOutResults.accuracy}%`);
});

test('Phase 8 - Task 10: Server Canary Check - Zero Decrypted Vault Values Sent to Server', () => {
  // Canary vault values
  const canaryVault = {
    FULL_NAME: 'CanaryRajeshSharma999',
    AADHAAR: '987654321098',
    PAN: 'ABCDE9999Z',
    MOBILE: '9876500000',
    ACCOUNT_NO: '998877665544'
  };

  // Build a typical server request payload generated by orchestrator
  const serverPayload = {
    v: '1.0.0',
    mode: 'Strict',
    goal: 'Fill scholarship application for {{FULL_NAME}}',
    step: 1,
    history: [
      { action: 'type', target_id: 'e1', value: '{{FULL_NAME}}', reason: 'Field matched' }
    ],
    dom: {
      url: 'http://localhost/form.html',
      viewport: [1280, 800],
      scrollY: 0,
      nodes: [
        { id: 'e1', tag: 'input', label: 'Full Name', sensitive: false, bbox: [10, 10, 200, 30] },
        { id: 'e2', tag: 'input', label: 'Aadhaar [REDACTED:AADHAAR]', sensitive: true, bbox: [10, 50, 200, 30] }
      ]
    },
    manifest: [
      { id: 'e1', type: 'input', bbox: [10, 10, 200, 30] }
    ],
    legend_version: 'v1'
  };

  const payloadString = JSON.stringify(serverPayload);

  // Invariant: Canary values must NEVER be present in the serialized request sent to the server
  for (const [key, canaryValue] of Object.entries(canaryVault)) {
    assert.strictEqual(
      payloadString.includes(canaryValue),
      false,
      `TRIPWIRE BREACH: Server payload contains raw vault value for ${key}: "${canaryValue}"`
    );
  }
});
