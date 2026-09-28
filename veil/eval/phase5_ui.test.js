const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Polyfill SubtleCrypto if needed in test environment
if (!globalThis.crypto?.subtle) {
  globalThis.crypto = crypto.webcrypto;
}

const ModelLoader = require('../extension/privacy/model-loader.js');
const VisionRunner = require('../extension/privacy/vision-runner.js');
const VisionWorker = require('../extension/workers/vision.worker.js');
const manifest = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../extension/models/manifest.json'), 'utf8'));

test('Phase 5 Test 1: Tampered Model File Rejected (Hash Verification & Invariant 12)', async () => {
  const modelInfo = manifest.models.yolox_nano;
  assert.ok(modelInfo, 'Manifest must contain yolox_nano entry');
  assert.strictEqual(modelInfo.license, 'Apache-2.0', 'Model license must be Apache-2.0');

  // 1. Verify legitimate model file passes SHA-256 verification
  ModelLoader.clearMemoryCache();
  const validBuffer = await ModelLoader.loadModel('yolox_nano');
  assert.ok(validBuffer.byteLength > 1000000, 'Valid model buffer must be loaded');

  // 2. Tampered buffer (single byte change) throws security violation
  const tamperedBuffer = validBuffer.slice(0);
  const view = new Uint8Array(tamperedBuffer);
  view[100] ^= 0xff; // Invert byte

  await assert.rejects(
    () => ModelLoader.verifyModelBuffer(tamperedBuffer, modelInfo.sha256),
    /SECURITY VIOLATION: Model hash mismatch/,
    'Tampered model buffer must throw SHA-256 security violation error'
  );
});

test('Phase 5 Test 2: Missing Model Falls Back Cleanly to DOM Only (Invariant 15)', async () => {
  const domNodes = [
    { id: 'btn_1', tag: 'button', role: 'button', bbox: [100, 100, 120, 40] },
    { id: 'inp_1', tag: 'input', type: 'text', bbox: [100, 160, 200, 36] }
  ];

  // Mock canvas context
  const mockCtx = {
    canvas: { width: 800, height: 600 },
    getImageData: () => ({ data: new Uint8ClampedArray(800 * 600 * 4) })
  };

  // Temporarily simulate missing model by pointing to nonexistent model
  const originalLoad = ModelLoader.loadModel;
  ModelLoader.loadModel = async () => {
    throw new Error('Model asset unavailable / missing from disk');
  };

  try {
    const result = await VisionRunner.runUIContextDetection(mockCtx, domNodes, { timeoutMs: 1500 });

    assert.strictEqual(result.degraded, true, 'Result must indicate degraded mode');
    assert.deepStrictEqual(result.fusedNodes, domNodes, 'Must return original DOM nodes untouched');
    assert.strictEqual(result.visualOnlyNodes.length, 0, 'No visual_only nodes should be created');
  } finally {
    ModelLoader.loadModel = originalLoad;
  }
});

test('Phase 5 Test 3: Forced Timeout Falls Back Cleanly to DOM Only (Invariant 15)', async () => {
  const domNodes = [
    { id: 'btn_dom', tag: 'button', role: 'button', bbox: [50, 50, 100, 30] }
  ];

  const mockCtx = {
    canvas: { width: 400, height: 300 },
    getImageData: () => ({ data: new Uint8ClampedArray(400 * 300 * 4) })
  };

  // Force timeout with budget of -1 ms
  const result = await VisionRunner.runUIContextDetection(mockCtx, domNodes, { timeoutMs: -1 });

  assert.strictEqual(result.degraded, true, 'Forced timeout must degrade cleanly');
  assert.deepStrictEqual(result.fusedNodes, domNodes, 'Timeout must preserve original DOM nodes without crashing');
  assert.strictEqual(result.visualOnlyNodes.length, 0, 'Timeout must create zero visual_only nodes');
});

test('Phase 5 Test 4: DOM-Vision Fusion on Canvas-Style Test Page (Task 4 & Invariant 14)', () => {
  // Scenario matching template_canvas_ui.html:
  // DOM contains a canvas element and a DOM reset button.
  // Vision detector finds 4 visual widgets rendered inside the canvas.
  const domNodes = [
    { id: 'btn_dom_reset', tag: 'button', role: 'button', bbox: [620, 24, 140, 36] },
    { id: 'app_canvas', tag: 'canvas', bbox: [50, 80, 760, 340] }
  ];

  const detections = [
    // Visual widget 1: Canvas Submit Button (inside canvas, no DOM element)
    { class: 'button', box: [100, 240, 180, 44], confidence: 0.92 },
    // Visual widget 2: Canvas Search Box (inside canvas, no DOM element)
    { class: 'text_input', box: [100, 160, 340, 40], confidence: 0.89 },
    // Visual widget 3: Matches DOM reset button closely (IoU ~ 0.85)
    { class: 'button', box: [622, 25, 138, 35], confidence: 0.94 }
  ];

  const viewport = [1280, 800];
  const redactions = [];

  const fusion = VisionRunner.fuseDomAndVisualDetections(domNodes, detections, viewport, redactions);

  // 1. Matched DOM element check
  assert.strictEqual(fusion.matchedDomCount, 1, 'DOM reset button must be matched');
  const matchedReset = fusion.fusedNodes.find((n) => n.id === 'btn_dom_reset');
  assert.ok(matchedReset.visual_match, 'Matched DOM node must record visual match metadata');
  assert.strictEqual(matchedReset.visual_match.class, 'button');

  // 2. Visual-only nodes created with sequential IDs (vo1, vo2...)
  assert.strictEqual(fusion.visualOnlyNodes.length, 2, '2 canvas widgets without DOM nodes must become visual_only');
  assert.strictEqual(fusion.visualOnlyNodes[0].id, 'vo1');
  assert.strictEqual(fusion.visualOnlyNodes[0].role, 'visual_only');
  assert.strictEqual(fusion.visualOnlyNodes[0].tag, 'button');
  assert.strictEqual(fusion.visualOnlyNodes[0].text, null, 'Visual-only nodes must NEVER contain text tokens');

  assert.strictEqual(fusion.visualOnlyNodes[1].id, 'vo2');
  assert.strictEqual(fusion.visualOnlyNodes[1].role, 'visual_only');
  assert.strictEqual(fusion.visualOnlyNodes[1].tag, 'text_input');
  assert.strictEqual(fusion.visualOnlyNodes[1].text, null, 'Visual-only nodes must NEVER contain text tokens');

  // 3. Fused nodes contains both DOM nodes and visual-only nodes
  assert.strictEqual(fusion.fusedNodes.length, 4, 'Fused nodes list must contain 2 DOM + 2 visual_only');
});

test('Phase 5 Test 5: Coordinate Click Validation - Rejection Rules (Invariant 16 & Task 4)', () => {
  const visualNode = {
    id: 'vo1',
    tag: 'button',
    role: 'visual_only',
    bbox: [100, 200, 150, 40] // [x, y, w, h] -> x in [100, 250], y in [200, 240]
  };

  const viewport = [1280, 800];
  const redactions = [
    { id: 'redact_face_1', type: 'face', bbox: [120, 210, 30, 20] } // Redacted sub-box inside vo1
  ];

  // Rule 1: Typing into visual_only nodes is strictly forbidden
  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'type', target_id: 'vo1', value: 'secret' }, visualNode, viewport, redactions),
    /Action rejected: typing into visual_only nodes is strictly forbidden/,
    'Typing into visual_only node must be rejected'
  );

  // Rule 2: Non-click actions are rejected
  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'select', target_id: 'vo1', value: 'opt1' }, visualNode, viewport, redactions),
    /Action rejected: visual_only nodes may only be targeted by coordinate click/,
    'Select action on visual_only node must be rejected'
  );

  // Rule 3: Coordinate click OUTSIDE bounding box is rejected
  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'click', target_id: 'vo1', coords: [300, 220] }, visualNode, viewport, redactions),
    /is outside bounding box/,
    'Click outside box width must be rejected'
  );

  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'click', target_id: 'vo1', coords: [150, 290] }, visualNode, viewport, redactions),
    /is outside bounding box/,
    'Click outside box height must be rejected'
  );

  // Rule 4: Coordinate click OFF-SCREEN / OUTSIDE viewport is rejected
  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'click', target_id: 'vo1', coords: [-10, 220] }, visualNode, viewport, redactions),
    /is outside bounding box|outside visible viewport/,
    'Negative coordinate must be rejected'
  );

  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'click', target_id: 'vo1', coords: [150, 950] }, visualNode, viewport, redactions),
    /is outside bounding box|outside visible viewport/,
    'Coordinate beyond viewport height must be rejected'
  );

  // Rule 5: Coordinate click intersecting REDACTED / sensitive region is rejected
  assert.throws(
    () => VisionRunner.validateVisualClick({ action: 'click', target_id: 'vo1', coords: [130, 215] }, visualNode, viewport, redactions),
    /intersects redacted\/sensitive region/,
    'Click intersecting redacted region must be rejected'
  );

  // Rule 6: Legitimate in-box, in-viewport, non-redacted click SUCCEEDS
  const validClick = VisionRunner.validateVisualClick(
    { action: 'click', target_id: 'vo1', coords: [180, 220] },
    visualNode,
    viewport,
    redactions
  );
  assert.strictEqual(validClick.valid, true);
  assert.deepStrictEqual(validClick.coords, [180, 220]);
});

test('Phase 5 Teardown: Unload Models & Clean Exit', () => {
  VisionWorker.unloadModels();
  ModelLoader.clearMemoryCache();
  VisionRunner.clearVerdictCache();
});

