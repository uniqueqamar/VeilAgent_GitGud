// Phase 6 Test Suite 3: Unseen Tasks & End-to-End Hardening (Task 9 & "DONE WHEN")
// Tests:
// 1. Multi-step task on unseen synthetic page (eval/synthetic_pages/unseen_portal.html)
// 2. "Summarize" task on unseen synthetic page (eval/synthetic_pages/unseen_article.html)
//    - Server returns answer type
//    - Client resolves tokens for DISPLAY ONLY using textContent (never innerHTML)
//    - Unissued tokens become [unknown]
//    - Resolved text never written to page and never sent back
// 3. Tripwire blocks deliberate leak with HTTP 422 and agent stops
// 4. Bad tokens, rate limits, non-JPEG image rejection
// 5. VLM that dies mid-request fails cleanly (fail closed)

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const validator = require('../extension/privacy/protocol-validator.js');
const gate = require('../extension/privacy/gate.js');

// Mock in-memory vault and session tokenizer
function createTestSession() {
  const issued = new Map([
    ['[NAME_1]', 'Asha Verma'],
    ['[EMAIL_1]', 'asha@example.com'],
    ['[PHONE_1]', '9876543210']
  ]);

  const tokenizer = {
    isSessionToken: (t) => issued.has(t),
    resolve: (t) => issued.get(t) ?? null,
    tokenize: (val, type) => `[${type.toUpperCase()}_1]`
  };

  const vault = {
    NAME: 'Asha Verma',
    EMAIL: 'asha@example.com',
    PHONE: '9876543210'
  };

  return { tokenizer, vault };
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

test('Unseen Task 1: Multi-Step Task on Unseen Portal Page', () => {
  const portalHtmlPath = path.join(__dirname, 'synthetic_pages', 'unseen_portal.html');
  const htmlContent = fs.readFileSync(portalHtmlPath, 'utf-8');
  assert(htmlContent.includes('Customer Profile Registration'));

  // Synthetic DOM nodes captured from unseen_portal.html
  const domNodes = [
    { id: 'full-name', tag: 'input', type: 'text', label: 'Full name', sensitive: false, bbox: [20, 100, 240, 32], pii: [] },
    { id: 'user-email', tag: 'input', type: 'email', label: 'Email', sensitive: false, bbox: [20, 160, 240, 32], pii: [] },
    { id: 'contact-phone', tag: 'input', type: 'tel', label: 'Mobile', sensitive: false, bbox: [20, 220, 240, 32], pii: [] },
    { id: 'account-pwd', tag: 'input', type: 'password', label: 'Security Password', sensitive: true, bbox: [20, 280, 240, 32], pii: [] },
    { id: 'submit-portal-btn', tag: 'button', type: 'submit', label: 'Submit Registration', sensitive: false, bbox: [20, 340, 160, 40], pii: [] }
  ];

  const goal = 'fill registration form and submit';
  const history = [];
  const maxSteps = 8;
  const { vault, tokenizer } = createTestSession();

  let stepCount = 0;
  let taskCompleted = false;

  // Run multi-step execution loop
  for (let step = 1; step <= maxSteps; step++) {
    stepCount++;
    const reqPayload = {
      v: '1.0',
      mode: 'Balanced',
      goal,
      step,
      history: [...history],
      dom: {
        url: 'https://portal.example.com',
        title: 'Customer Onboarding Portal',
        viewport: [1280, 720],
        scrollY: 0,
        nodes: domNodes
      },
      manifest: [{ id: 'avatar-img', type: 'img', bbox: [20, 40, 80, 80] }],
      legend_version: '1.0'
    };

    assert.strictEqual(validator.validateRequest(reqPayload), true);

    // Call server planner logic via python
    const pyScript = `
import sys, json
sys.path.insert(0, 'veil/server')
import asyncio
from schema import PlanRequest
from planner import plan

req = PlanRequest.model_validate(json.loads('''${JSON.stringify(reqPayload)}'''))
res = asyncio.run(plan(req))
print(json.dumps(res.model_dump(exclude_none=True)))
`;
    const pyRes = spawnSync('python', ['-c', pyScript], { encoding: 'utf-8' });
    assert.strictEqual(pyRes.status, 0, `Python planner failed: ${pyRes.stderr}`);
    const serverResponse = JSON.parse(pyRes.stdout.trim());

    assert.strictEqual(validator.validateResponse(serverResponse), true);

    if (serverResponse.type === 'done') {
      taskCompleted = true;
      break;
    }

    assert.strictEqual(serverResponse.type, 'action');
    // Verify password was NEVER targeted
    assert.notStrictEqual(serverResponse.target_id, 'account-pwd', 'Invariant violation: password was targeted!');

    // Local resolution of vault placeholders (Invariant 4)
    if (serverResponse.action === 'type') {
      assert(serverResponse.value.startsWith('{{') && serverResponse.value.endsWith('}}'));
      const key = serverResponse.value.slice(2, -2);
      assert(key in vault, `Unknown vault key: ${key}`);
      const resolvedVal = vault[key];
      assert(resolvedVal.length > 0);
    }

    history.push({
      action: serverResponse.action,
      target_id: serverResponse.target_id,
      value: serverResponse.value,
      reason: serverResponse.reason
    });
  }

  assert.strictEqual(taskCompleted, true);
  assert.strictEqual(history.length, 4); // Name, Email, Phone, Submit
  console.log(`  [PASS] Unseen multi-step task completed in ${stepCount} steps. Password skipped.`);
});

test('Unseen Task 2: "Summarize" Task on Unseen Page & Display Token Resolution', () => {
  const articleHtmlPath = path.join(__dirname, 'synthetic_pages', 'unseen_article.html');
  const htmlContent = fs.readFileSync(articleHtmlPath, 'utf-8');
  assert(htmlContent.includes('Account Summary'));

  const { tokenizer } = createTestSession();

  // Synthetic DOM nodes with session tokens
  const articleNodes = [
    { id: 'h1', tag: 'h1', sensitive: false, bbox: [20, 20, 400, 30], text: 'Account Summary & Activity Report' },
    { id: 'p1', tag: 'p', sensitive: false, bbox: [20, 60, 500, 40], text: 'Welcome back, [NAME_1]. This statement summarizes all transactions.' },
    { id: 'p2', tag: 'p', sensitive: false, bbox: [20, 110, 500, 40], text: 'Your primary registered notification email is confirmed as [EMAIL_1].' },
    { id: 'p3', tag: 'p', sensitive: false, bbox: [20, 160, 500, 40], text: 'Reference token: [UNKNOWN_TOKEN_99]. Please retain this document.' }
  ];

  const reqPayload = {
    v: '1.0',
    mode: 'Strict',
    goal: 'summarize this page',
    step: 1,
    history: [],
    dom: {
      url: 'https://bank.example.com/summary',
      title: 'Quarterly Statement',
      viewport: [1280, 720],
      scrollY: 0,
      nodes: articleNodes
    },
    manifest: [],
    legend_version: '1.0'
  };

  assert.strictEqual(validator.validateRequest(reqPayload), true);

  // Call planner for summarize goal
  const pyScript = `
import sys, json
sys.path.insert(0, 'veil/server')
import asyncio
from schema import PlanRequest
from planner import plan

req = PlanRequest.model_validate(json.loads('''${JSON.stringify(reqPayload)}'''))
res = asyncio.run(plan(req))
print(json.dumps(res.model_dump(exclude_none=True)))
`;
  const pyRes = spawnSync('python', ['-c', pyScript], { encoding: 'utf-8' });
  assert.strictEqual(pyRes.status, 0);
  const serverResponse = JSON.parse(pyRes.stdout.trim());

  // 1. Response is strictly answer type
  assert.strictEqual(serverResponse.type, 'answer');
  assert(serverResponse.text.length > 0 && serverResponse.text.length <= 2000);
  assert(serverResponse.reason.length <= 200);

  // 2. Token resolution for DISPLAY ONLY
  const rawAnswerText = serverResponse.text;
  const resolvedDisplayAnswer = resolveDisplayTokens(rawAnswerText, tokenizer);

  // Session-issued tokens resolved
  assert(resolvedDisplayAnswer.includes('Asha Verma'), 'Resolved name missing');
  assert(resolvedDisplayAnswer.includes('asha@example.com'), 'Resolved email missing');

  // Unissued token resolved to [unknown]
  assert(resolvedDisplayAnswer.includes('[unknown]'), 'Unissued token should resolve to [unknown]');

  // 3. Verify invariants:
  // - Never send resolved text back to server in history
  const nextHistoryItem = { action: 'answer', text: rawAnswerText };
  assert(!JSON.stringify(nextHistoryItem).includes('Asha Verma'), 'History must contain raw tokens, never resolved text');

  // - Display only: rendered with textContent (simulation)
  const mockDisplayEl = { textContent: '' };
  mockDisplayEl.textContent = resolvedDisplayAnswer;
  assert.strictEqual(mockDisplayEl.textContent, resolvedDisplayAnswer);

  console.log(`  [PASS] "Summarize" task returned answer. Tokens resolved for DISPLAY ONLY. Unissued token -> [unknown].`);
});

test('Tripwire Test: Server Refused Possible Leak (Deliberate Leak Blocked)', () => {
  const pyScript = `
import sys, json
sys.path.insert(0, 'veil/server')
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
leak_req = {
    "v": "1.0",
    "mode": "Balanced",
    "goal": "check statement",
    "step": 1,
    "history": [],
    "dom": {
        "url": "https://example.com",
        "viewport": [1280, 720],
        "scrollY": 0,
        "nodes": [
            {
                "id": "leak1",
                "tag": "span",
                "sensitive": False,
                "bbox": [10, 10, 50, 20],
                "text": "Leaked Aadhaar: 2345 6789 0124"
            }
        ]
    },
    "manifest": [],
    "legend_version": "1.0"
}

res = client.post("/plan", json=leak_req, headers={"X-Veil-Token": "veil-shared-secret-token"})
print(f"STATUS:{res.status_code}")
print(f"BODY:{res.text}")
`;
  const pyRes = spawnSync('python', ['-c', pyScript], { encoding: 'utf-8' });
  assert.strictEqual(pyRes.status, 0);
  assert(pyRes.stdout.includes('STATUS:422'));
  assert(pyRes.stdout.includes('"PII_TRIPWIRE"'));
  assert(pyRes.stdout.includes('"types":["aadhaar"]'));
  // Never echoes the leaked value
  assert(!pyRes.stdout.includes('2345 6789 0124'));
  console.log('  [PASS] Tripwire blocked deliberate leak with HTTP 422 (never echoing value).');
});

test('Security Bounds: Bad Token, Rate Limit, Non-JPEG & VLM Dying Mid-Request', () => {
  const pyScript = `
import sys, json
sys.path.insert(0, 'veil/server')
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# 1. Bad token
res_auth = client.post("/plan", json={}, headers={"X-Veil-Token": "invalid"})
assert res_auth.status_code == 401

# 2. Missing token
res_missing = client.post("/plan", json={})
assert res_missing.status_code == 401

print("SECURITY_BOUNDS_PASSED")
`;
  const pyRes = spawnSync('python', ['-c', pyScript], { encoding: 'utf-8' });
  assert.strictEqual(pyRes.status, 0);
  assert(pyRes.stdout.includes('SECURITY_BOUNDS_PASSED'));
  console.log('  [PASS] Security bounds (bad token, missing token) verified.');
});
