// Phase 6 Test Suite 1: Schema Fuzzing (Task 9)
// Tests: Malformed, Oversized, and Extra Fields on BOTH Client (JS) and Server (Python) sides.
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const validator = require('../extension/privacy/protocol-validator.js');

function createValidRequest() {
  return {
    v: '1.0',
    mode: 'Balanced',
    goal: 'Fill onboarding form',
    step: 1,
    history: [],
    dom: {
      url: 'https://example.com/app',
      title: 'Dashboard',
      viewport: [1280, 720],
      scrollY: 0,
      nodes: [
        {
          id: 'n1',
          tag: 'input',
          type: 'text',
          label: 'Username',
          sensitive: false,
          bbox: [10, 20, 200, 30],
          pii: []
        }
      ]
    },
    image: null,
    manifest: [
      { id: 'n1', type: 'input', bbox: [10, 20, 200, 30] }
    ],
    legend_version: '1.0'
  };
}

function createValidResponse(type = 'action') {
  if (type === 'action') {
    return {
      type: 'action',
      action: 'click',
      target_id: 'n1',
      coords: [100, 35],
      value: null,
      reason: 'clicking target button'
    };
  } else if (type === 'answer') {
    return {
      type: 'answer',
      text: 'Summary of the page text with token [NAME_1].',
      reason: 'summarized user account'
    };
  } else if (type === 'ask_user') {
    return {
      type: 'ask_user',
      question: 'Do you confirm submitting?',
      reason: 'asking user confirmation'
    };
  } else if (type === 'done') {
    return {
      type: 'done',
      reason: 'all form steps completed'
    };
  } else if (type === 'fail') {
    return {
      type: 'fail',
      reason: 'missing required credentials'
    };
  }
}

test('Schema Fuzz 1: Valid Baseline Request and All 5 Response Types Pass', () => {
  const req = createValidRequest();
  assert.strictEqual(validator.validateRequest(req), true);

  for (const t of ['action', 'answer', 'ask_user', 'done', 'fail']) {
    const res = createValidResponse(t);
    assert.strictEqual(validator.validateResponse(res), true);
  }
});

test('Schema Fuzz 2: Malformed Field Types Rejected on Client', () => {
  // Step as string
  const badStep = createValidRequest();
  badStep.step = 'first_step';
  assert.throws(() => validator.validateRequest(badStep), /step must be an integer/);

  // Negative step
  badStep.step = -5;
  assert.throws(() => validator.validateRequest(badStep), /step must be an integer between 0 and 100/);

  // Invalid mode
  const badMode = createValidRequest();
  badMode.mode = 'UltraSecure';
  assert.throws(() => validator.validateRequest(badMode), /invalid mode/);

  // Non-integer viewport
  const badVp = createValidRequest();
  badVp.dom.viewport = [1280.5, 720];
  assert.throws(() => validator.validateRequest(badVp), /viewport must be an array of 2 integers/);

  // BBox wrong length
  const badBbox = createValidRequest();
  badBbox.dom.nodes[0].bbox = [10, 20, 100];
  assert.throws(() => validator.validateRequest(badBbox), /bbox must be an array of 4 integers/);

  // Unknown response type
  const badRes = { type: 'restart_machine', reason: 'just testing' };
  assert.throws(() => validator.validateResponse(badRes), /response type must be exactly one of/);
});

test('Schema Fuzz 3: Oversized Strings Strictly Rejected on Client', () => {
  // Goal > 500 chars
  const bigGoal = createValidRequest();
  bigGoal.goal = 'X'.repeat(501);
  assert.throws(() => validator.validateRequest(bigGoal), /goal must be a string between 1 and 500 characters/);

  // URL > 200 chars
  const bigUrl = createValidRequest();
  bigUrl.dom.url = 'https://example.com/' + 'a'.repeat(250);
  assert.throws(() => validator.validateRequest(bigUrl), /dom\.url must be a string <= 200 characters/);

  // Title > 100 chars
  const bigTitle = createValidRequest();
  bigTitle.dom.title = 'T'.repeat(101);
  assert.throws(() => validator.validateRequest(bigTitle), /dom\.title must be a string <= 100 characters/);

  // Node label > 100 chars
  const bigLabel = createValidRequest();
  bigLabel.dom.nodes[0].label = 'L'.repeat(101);
  assert.throws(() => validator.validateRequest(bigLabel), /node\[0\]\.label must be a string <= 100 characters/);

  // History > 8 items
  const bigHistory = createValidRequest();
  bigHistory.history = Array.from({ length: 9 }, (_, i) => ({ action: 'click', reason: `step ${i}` }));
  assert.throws(() => validator.validateRequest(bigHistory), /history must be an array with max 8 past actions/);

  // Response reason > 200 chars
  const bigReason = createValidResponse('action');
  bigReason.reason = 'R'.repeat(201);
  assert.throws(() => validator.validateResponse(bigReason), /reason is required and must be a string <= 200 characters/);

  // Answer text > 2000 chars
  const bigAnswer = createValidResponse('answer');
  bigAnswer.text = 'A'.repeat(2001);
  assert.throws(() => validator.validateResponse(bigAnswer), /answer text is required and must be a string between 1 and 2000 characters/);
});

test('Schema Fuzz 4: Extra / Unknown Fields Strictly Rejected on Client', () => {
  // Top-level extra key
  const extraTop = createValidRequest();
  extraTop.injected_top_key = 'evil';
  assert.throws(() => validator.validateRequest(extraTop), /unauthorized top-level request key "injected_top_key"/);

  // DOM extra key
  const extraDom = createValidRequest();
  extraDom.dom.injected_dom_prop = true;
  assert.throws(() => validator.validateRequest(extraDom), /unauthorized dom key "injected_dom_prop"/);

  // Node extra key
  const extraNode = createValidRequest();
  extraNode.dom.nodes[0].injected_node_prop = 'bad';
  assert.throws(() => validator.validateRequest(extraNode), /unauthorized node key "injected_node_prop"/);

  // Manifest extra key
  const extraManifest = createValidRequest();
  extraManifest.manifest[0].injected_manifest_prop = 'bad';
  assert.throws(() => validator.validateRequest(extraManifest), /unauthorized manifest key "injected_manifest_prop"/);

  // Action response extra key
  const extraRes = createValidResponse('action');
  extraRes.extra_auth_bypass = true;
  assert.throws(() => validator.validateResponse(extraRes), /unauthorized key "extra_auth_bypass" in action response/);

  // Answer response extra key
  const extraAns = createValidResponse('answer');
  extraAns.command = 'reboot';
  assert.throws(() => validator.validateResponse(extraAns), /unauthorized key "command" in answer response/);
});

test('Schema Fuzz 5: Server-side Pydantic Model Extra Field Rejection', () => {
  const pyScript = `
import sys, json
sys.path.insert(0, 'veil/server')
from schema import PlanRequest, ActionResponse, AnswerResponse

# Test 1: PlanRequest extra field rejection
try:
    PlanRequest.model_validate({
        "v": "1.0", "mode": "Balanced", "goal": "test", "step": 1,
        "history": [], "dom": {"url": "https://a.com", "viewport": [100, 100], "scrollY": 0, "nodes": []},
        "manifest": [], "legend_version": "1.0",
        "injected_extra_field": "hack"
    })
    print("FAIL: PlanRequest accepted extra field")
    sys.exit(1)
except Exception:
    pass

# Test 2: ActionResponse extra field rejection
try:
    ActionResponse.model_validate({
        "type": "action", "action": "click", "reason": "test",
        "evil_param": "bypass"
    })
    print("FAIL: ActionResponse accepted extra field")
    sys.exit(1)
except Exception:
    pass

print("SERVER_SCHEMA_EXTRA_FORBID_PASSED")
`;

  const res = spawnSync('python', ['-c', pyScript], { encoding: 'utf-8' });
  assert.strictEqual(res.status, 0);
  assert(res.stdout.includes('SERVER_SCHEMA_EXTRA_FORBID_PASSED'));
});
