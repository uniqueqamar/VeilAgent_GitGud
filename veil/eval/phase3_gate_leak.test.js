const test = require('node:test');
const assert = require('node:assert');

// Dual-runtime worker and gate imports
const VeilPII = require('../extension/workers/pii.js');
globalThis.VeilPII = VeilPII;
const VeilGate = require('../extension/privacy/gate.js');

function createValidBasePayload() {
  return {
    goal: 'fill KYC application form',
    step: 1,
    dom: {
      url: 'http://127.0.0.1:8000',
      title: 'KYC Form',
      viewport: [1280, 720],
      scrollY: 0,
      nodes: [
        {
          id: 'e1',
          tag: 'input',
          role: null,
          type: 'text',
          label: 'Full name',
          text: null,
          autocomplete: null,
          sensitive: false,
          bbox: [10, 50, 200, 24],
          pii: []
        }
      ]
    },
    screenshot: null,
    redactions: [],
    history: [],
    mode: 'Strict'
  };
}

test('Gate Schema Allowlist: Unknown keys and limits rejected', () => {
  // 1. Unknown top-level key rejected
  const p1 = createValidBasePayload();
  p1.attacker_field = 'malicious';
  assert.throws(() => VeilGate.assertClean(p1), /GATE: unauthorized top-level key "attacker_field"/);

  // 2. Unknown dom key rejected
  const p2 = createValidBasePayload();
  p2.dom.cookies = 'session=123';
  assert.throws(() => VeilGate.assertClean(p2), /GATE: unauthorized dom key "cookies"/);

  // 3. Unknown node key rejected
  const p3 = createValidBasePayload();
  p3.dom.nodes[0].secret_token = 'xyz';
  assert.throws(() => VeilGate.assertClean(p3), /GATE: unauthorized node key "secret_token"/);

  // 4. Forbidden key 'value' inside DOM rejected
  const p4 = createValidBasePayload();
  p4.dom.nodes[0].value = 'User Entered Text';
  assert.throws(() => VeilGate.assertClean(p4), /GATE: forbidden field "value"/);

  // 5. Excessive goal string length rejected
  const p5 = createValidBasePayload();
  p5.goal = 'a'.repeat(501);
  assert.throws(() => VeilGate.assertClean(p5), /GATE: goal string exceeds 500 characters/);

  // 6. Excessive node label length rejected
  const p6 = createValidBasePayload();
  p6.dom.nodes[0].label = 'a'.repeat(41);
  assert.throws(() => VeilGate.assertClean(p6), /GATE: node label exceeds 40 characters/);
});

test('Gate Manifest Coverage: Screenshot requires complete redaction of all sensitive, PII, and media nodes', () => {
  const p = createValidBasePayload();
  p.mode = 'Balanced';
  p.screenshot = 'data:image/jpeg;base64,' + Buffer.from('fake-jpeg').toString('base64');
  p.redactions = [];

  // Media node without redaction -> must fail closed
  p.dom.nodes.push({
    id: 'e_img',
    tag: 'img',
    role: 'media',
    type: null,
    label: '',
    text: null,
    autocomplete: null,
    sensitive: true,
    bbox: [10, 100, 100, 100],
    pii: []
  });
  assert.throws(
    () => VeilGate.assertClean(p),
    /GATE: sensitive\/pii\/media node "e_img" missing from redaction manifest/
  );

  // Add redaction for e_img
  p.redactions.push({ id: 'e_img', type: 'media_img', bbox: [10, 100, 100, 100] });
  // Now e_img passes
  VeilGate.assertClean(p);

  // Sensitive input node without redaction -> must fail closed
  p.dom.nodes.push({
    id: 'e_pw',
    tag: 'input',
    role: null,
    type: 'password',
    label: 'Password',
    text: null,
    autocomplete: null,
    sensitive: true,
    bbox: [10, 220, 200, 24],
    pii: []
  });
  assert.throws(
    () => VeilGate.assertClean(p),
    /GATE: sensitive\/pii\/media node "e_pw" missing from redaction manifest/
  );

  // Add redaction for e_pw
  p.redactions.push({ id: 'e_pw', type: 'sensitive_input', bbox: [10, 220, 200, 24] });
  VeilGate.assertClean(p);

  // PII node without redaction -> must fail closed
  p.dom.nodes.push({
    id: 'e_text',
    tag: 'p',
    role: 'text',
    type: null,
    label: 'User Aadhaar',
    text: '[REDACTED:AADHAAR]',
    autocomplete: null,
    sensitive: true,
    bbox: [10, 260, 200, 20],
    pii: ['aadhaar']
  });
  assert.throws(
    () => VeilGate.assertClean(p),
    /GATE: sensitive\/pii\/media node "e_text" missing from redaction manifest/
  );

  // Add redaction for e_text
  p.redactions.push({ id: 'e_text', type: 'pii_aadhaar', bbox: [10, 260, 200, 20] });
  // Now fully covered
  VeilGate.assertClean(p);
});

test('Gate Leaky Payloads: Deliberately leaky payload per PII type is strictly blocked', () => {
  const LEAKY_SAMPLES = [
    { type: 'email', value: 'leak_user@domain.com', field: 'goal' },
    { type: 'mobile', value: '+91 9876543210', field: 'dom.title' },
    { type: 'aadhaar', value: '234567890124', field: 'dom.url' }, // valid Verhoeff (ends in 4)
    { type: 'pan', value: 'ABCPK1234F', field: 'node.label' }, // 4th char 'P' for individual
    { type: 'card', value: '4532 0151 1283 0366', field: 'node.text' }, // valid Luhn
    { type: 'ifsc', value: 'SBIN0001234', field: 'node.label' },
    { type: 'upi', value: 'merchant@okhdfcbank', field: 'node.text' },
    { type: 'passport', value: 'A1234567', field: 'node.label' },
    { type: 'voter_id', value: 'ABC1234567', field: 'node.text' },
    { type: 'driving_licence', value: 'DL1420110012345', field: 'node.text' },
    { type: 'plate', value: 'DL01AB1234', field: 'node.text' },
    { type: 'mobile', value: '9876543210', field: 'history.value' },
    { type: 'email', value: 'admin@company.org', field: 'history.reason' }
  ];

  for (const sample of LEAKY_SAMPLES) {
    const payload = createValidBasePayload();

    if (sample.field === 'goal') {
      payload.goal = `Action for ${sample.value}`;
    } else if (sample.field === 'dom.title') {
      payload.dom.title = `Profile of ${sample.value}`;
    } else if (sample.field === 'dom.url') {
      payload.dom.url = `http://127.0.0.1:8000/api/${sample.value}`;
    } else if (sample.field === 'node.label') {
      payload.dom.nodes[0].label = sample.value.slice(0, 40);
    } else if (sample.field === 'node.text') {
      payload.dom.nodes[0].text = `Contains ${sample.value}`;
    } else if (sample.field === 'history.value') {
      payload.history.push({ action: 'type', target_id: 'e1', value: sample.value, reason: 'fill field' });
    } else if (sample.field === 'history.reason') {
      payload.history.push({ action: 'type', target_id: 'e1', value: '{{NAME}}', reason: `for ${sample.value}` });
    }

    assert.throws(
      () => VeilGate.assertClean(payload),
      (err) => {
        assert.ok(err.message.includes('GATE: unredacted PII'), `Expected PII leak rejection for ${sample.type} in ${sample.field}, got: ${err.message}`);
        return true;
      },
      `Gate MUST block leaky payload for PII type: ${sample.type} in ${sample.field}`
    );
  }
});

test('Gate Tamper-Evident Receipts: SHA-256 hash chaining and export structure', async () => {
  const p1 = createValidBasePayload();
  p1.dom.nodes[0].pii = ['name'];

  const r1 = await VeilGate.createReceipt(p1, 500);
  assert.ok(r1.time, 'Receipt must have ISO timestamp');
  assert.strictEqual(r1.mode, 'Strict');
  assert.strictEqual(r1.bytes, 500);
  assert.deepStrictEqual(r1.counts, { name: 1 });
  assert.strictEqual(r1.hashPrev, '0000000000000000000000000000000000000000000000000000000000000000');
  assert.strictEqual(typeof r1.hash, 'string');
  assert.strictEqual(r1.hash.length, 64, 'SHA-256 hash must be 64 hex characters');

  // Step 2 receipt must chain to r1.hash
  const p2 = createValidBasePayload();
  p2.step = 2;
  const r2 = await VeilGate.createReceipt(p2, 650);
  assert.strictEqual(r2.hashPrev, r1.hash, 'Step 2 hashPrev must match Step 1 hash');
  assert.notStrictEqual(r2.hash, r1.hash, 'Step 2 hash must differ from Step 1');

  // Export audit chain
  const auditExport = VeilGate.exportReceipts();
  assert.strictEqual(auditExport.type, 'tamper-evident-audit-chain');
  assert.strictEqual(auditExport.head, r2.hash);
  assert.ok(auditExport.receipts.length >= 2);

  // Verify no raw PII values are leaked in the receipt chain
  const jsonExport = JSON.stringify(auditExport);
  assert.ok(!jsonExport.includes('Asha'), 'No PII values permitted in audit receipts');
  assert.ok(!jsonExport.includes('asha@example.com'), 'No PII values permitted in audit receipts');
});
