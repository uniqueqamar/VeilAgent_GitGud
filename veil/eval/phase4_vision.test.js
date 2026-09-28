const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Load modules
const MODEL_MANIFEST_PATH = path.resolve(__dirname, '../extension/models/manifest.json');
const manifest = JSON.parse(fs.readFileSync(MODEL_MANIFEST_PATH, 'utf8'));

// Polyfill SubtleCrypto if needed in test environment
if (!globalThis.crypto?.subtle) {
  globalThis.crypto = crypto.webcrypto;
}

const ModelLoader = require('../extension/privacy/model-loader.js');
const VisionRunner = require('../extension/privacy/vision-runner.js');
const VisionWorker = require('../extension/workers/vision.worker.js');

test('Task 10.1: Model Loader Integrity Check - Valid vs Tampered SHA-256 Buffer', async () => {
  const modelName = 'ultraface_rfb_320';
  const expectedHash = manifest.models[modelName].sha256;
  assert.ok(expectedHash, 'Manifest must contain sha256 for ultraface');

  // Create an exact typed array buffer and compute its SHA-256
  const validData = new Uint8Array(Buffer.from('VALID_ONNX_MODEL_BINARY_MOCK_DATA_0123456789'));
  const validHash = crypto.createHash('sha256').update(validData).digest('hex');

  // 1. Valid buffer matching target hash
  const actualHash = await ModelLoader.verifyModelBuffer(validData, validHash);
  assert.strictEqual(actualHash, validHash, 'Matching hash must pass verification');

  // 2. Tampered buffer (single byte change) throws security violation
  const tamperedData = new Uint8Array(Buffer.from('VALID_ONNX_MODEL_BINARY_MOCK_DATA_0123456789'));
  tamperedData[0] = 0x58; // Flip first byte
  await assert.rejects(
    () => ModelLoader.verifyModelBuffer(tamperedData, validHash),
    /SECURITY VIOLATION: Model hash mismatch/,
    'Tampered buffer must throw SHA-256 security violation error'
  );

  // 3. Hash mismatch in loadModel throws security error
  const mockManifest = {
    models: {
      fake_model: {
        file: null,
        sha256: '0000000000000000000000000000000000000000000000000000000000000000',
        url: 'https://example.com/fake_model.onnx'
      }
    }
  };
  await assert.rejects(
    async () => {
      // Mock fetch returning tampered data
      globalThis.fetch = async () => ({
        ok: true,
        arrayBuffer: async () => tamperedData.buffer
      });
      await ModelLoader.loadModel('fake_model', mockManifest);
    },
    /SECURITY VIOLATION: Model hash mismatch/,
    'Tampered model load must throw security mismatch exception'
  );
});

test('Task 10.2: Box Expansion & Coordinate Math', () => {
  // UltraFace 20% expansion bias for recall
  const origBox = [100, 100, 50, 50]; // [x, y, w, h]
  const expandRatio = 0.20;

  const [x, y, w, h] = origBox;
  const dw = Math.round(w * expandRatio);
  const dh = Math.round(h * expandRatio);
  const expanded = [x - dw, y - dh, w + 2 * dw, h + 2 * dh];

  assert.deepStrictEqual(expanded, [90, 90, 70, 70]);

  // Clamping to crop bounds [0, 0, 200, 200]
  const boundaryBox = [-10, -5, 80, 80];
  const clamped = [
    Math.max(0, boundaryBox[0]),
    Math.max(0, boundaryBox[1]),
    Math.min(200 - Math.max(0, boundaryBox[0]), boundaryBox[2]),
    Math.min(200 - Math.max(0, boundaryBox[1]), boundaryBox[3])
  ];
  assert.deepStrictEqual(clamped, [0, 0, 80, 80]);
});

test('Task 10.3: Decision Table & Fail-Closed Invariants', async () => {
  // Mock canvas 2D context
  const mockCtx = {
    canvas: { width: 1000, height: 800 },
    getImageData: (x, y, w, h) => ({
      data: new Uint8ClampedArray(w * h * 4).fill(200) // uniform gray image
    })
  };

  // Case A: Harmless media element -> vision OK, zero sensitive regions -> safely un-black
  const harmlessNode = [{ id: 'img_harmless', tag: 'img', bbox: [50, 50, 200, 150] }];
  // Mock worker detect returning 0 faces, 0 words
  globalThis.VeilVisionWorker = {
    detect: async () => ({
      faces: [],
      words: [],
      backend: 'wasm',
      ms: 15
    })
  };

  VisionRunner.clearVerdictCache();
  const resHarmless = await VisionRunner.evaluateMediaWithVision(mockCtx, harmlessNode);
  assert.strictEqual(resHarmless.boxesToRedact.length, 0, 'Harmless image should not have redaction boxes');
  assert.ok(resHarmless.clearedMediaIds.has('img_harmless'), 'Harmless image must be in clearedMediaIds');

  // Case B: Media with detected face -> redact face box, parent element remains un-blacked
  const faceNode = [{ id: 'img_portrait', tag: 'img', bbox: [100, 100, 200, 200] }];
  globalThis.VeilVisionWorker = {
    detect: async () => ({
      faces: [{ box: [40, 30, 80, 80], conf: 0.92 }],
      words: [],
      backend: 'wasm',
      ms: 22
    })
  };

  VisionRunner.clearVerdictCache();
  const resFace = await VisionRunner.evaluateMediaWithVision(mockCtx, faceNode);
  assert.strictEqual(resFace.boxesToRedact.length, 1);
  assert.strictEqual(resFace.boxesToRedact[0].type, 'face');
  assert.strictEqual(resFace.boxesToRedact[0].parentId, 'img_portrait');
  assert.ok(resFace.clearedMediaIds.has('img_portrait'), 'Media parent is cleared while sub-box is blacked out');

  // Case C: Worker throws exception -> FAIL CLOSED (solid black for entire element)
  globalThis.VeilVisionWorker = {
    detect: async () => {
      throw new Error('Worker crash / ONNX runtime failure');
    }
  };

  VisionRunner.clearVerdictCache();
  const resError = await VisionRunner.evaluateMediaWithVision(mockCtx, harmlessNode);
  assert.strictEqual(resError.boxesToRedact.length, 1);
  assert.strictEqual(resError.boxesToRedact[0].id, 'img_harmless');
  assert.strictEqual(resError.boxesToRedact[0].fullElement, true);
  assert.strictEqual(resError.clearedMediaIds.has('img_harmless'), false);
  assert.strictEqual(resError.metrics.elementsBlackedOut, 1);

  // Case D: Vision timeout (> timeoutMs) -> FAIL CLOSED (solid black for entire element)
  globalThis.VeilVisionWorker = {
    detect: async () => ({
      timeout: true,
      faces: [],
      words: [],
      backend: 'wasm'
    })
  };

  VisionRunner.clearVerdictCache();
  const resTimeout = await VisionRunner.evaluateMediaWithVision(mockCtx, harmlessNode, { timeoutMs: 100 });
  assert.strictEqual(resTimeout.boxesToRedact.length, 1);
  assert.strictEqual(resTimeout.boxesToRedact[0].fullElement, true);
  assert.strictEqual(resTimeout.clearedMediaIds.has('img_harmless'), false);

  // Case E: Crop looks like ID / document layout with uncertain OCR -> FAIL CLOSED
  globalThis.VeilVisionWorker = {
    detect: async () => ({
      cropLooksLikeId: true,
      faces: [{ box: [10, 10, 50, 50], conf: 0.8 }],
      words: [],
      backend: 'wasm'
    })
  };

  VisionRunner.clearVerdictCache();
  const resIdLayout = await VisionRunner.evaluateMediaWithVision(mockCtx, harmlessNode);
  assert.strictEqual(resIdLayout.boxesToRedact.length, 1);
  assert.strictEqual(resIdLayout.boxesToRedact[0].fullElement, true, 'ID card appearance must black out entire element');
  assert.strictEqual(resIdLayout.clearedMediaIds.has('img_harmless'), false);

  // Case F: Cross-origin iframe -> NEVER inspected, always solid black
  const iframeNode = [{ id: 'iframe_cross', tag: 'iframe', crossorigin: true, bbox: [0, 0, 300, 200] }];
  const resIframe = await VisionRunner.evaluateMediaWithVision(mockCtx, iframeNode);
  assert.strictEqual(resIframe.boxesToRedact.length, 1);
  assert.strictEqual(resIframe.boxesToRedact[0].id, 'iframe_cross');
  assert.strictEqual(resIframe.boxesToRedact[0].fullElement, true);
});

test('Task 10.4: Perceptual dHash Caching', () => {
  // Two identical 100x100 white blocks
  const img1 = new Uint8ClampedArray(100 * 100 * 4).fill(255);
  const img2 = new Uint8ClampedArray(100 * 100 * 4).fill(255);

  const hash1 = VisionRunner.computeCropDHash(img1, 100, 100);
  const hash2 = VisionRunner.computeCropDHash(img2, 100, 100);

  assert.strictEqual(hash1, hash2, 'Identical crops must produce identical perceptual hashes');

  // Slightly modified pixel block
  const img3 = new Uint8ClampedArray(100 * 100 * 4);
  for (let i = 0; i < img3.length; i += 4) {
    img3[i] = (i % 256); // Gradient
    img3[i + 1] = 100;
    img3[i + 2] = 50;
    img3[i + 3] = 255;
  }
  const hash3 = VisionRunner.computeCropDHash(img3, 100, 100);
  assert.notStrictEqual(hash1, hash3, 'Different image content must yield different hash');
});

test('Task 10.5: Stress Test - 20+ Images Time Budget Enforcement', async () => {
  const images = [];
  for (let i = 0; i < 25; i++) {
    images.push({
      id: `img_grid_${i}`,
      tag: 'img',
      bbox: [(i % 5) * 150, Math.floor(i / 5) * 150, 120, 120]
    });
  }

  let calls = 0;
  globalThis.VeilVisionWorker = {
    detect: async (_crop, opts) => {
      calls++;
      // Simulate 80ms inference per image
      await new Promise((r) => setTimeout(r, 70));
      return { faces: [], words: [], backend: 'wasm' };
    }
  };

  const mockCtx = {
    canvas: { width: 1200, height: 1000 },
    getImageData: (sx, sy, sw, sh) => {
      const seed = sx * 13 + sy * 37 + 1;
      const arr = new Uint8ClampedArray(sw * sh * 4);
      for (let i = 0; i < arr.length; i += 4) {
        arr[i] = (Math.sin(seed + i) * 127 + 128) | 0;
        arr[i + 1] = (Math.cos(seed + i * 2) * 127 + 128) | 0;
        arr[i + 2] = (Math.sin(seed + i * 3) * 127 + 128) | 0;
        arr[i + 3] = 255;
      }
      return { data: arr };
    }
  };

  VisionRunner.clearVerdictCache();
  const timeBudget = 400; // 400ms budget for test speed
  const startTime = Date.now();
  const result = await VisionRunner.evaluateMediaWithVision(mockCtx, images, { timeoutMs: timeBudget });
  const totalElapsed = Date.now() - startTime;

  // The runner must stop calling detect once time budget expires
  assert.ok(calls < 25, `Expected runner to stop before processing all 25 images (processed: ${calls})`);
  // All unprocessed images must fail closed (solid black)
  assert.strictEqual(result.boxesToRedact.length + result.clearedMediaIds.size, 25);
  assert.ok(result.metrics.fallbackReasons.some((r) => r.includes('timeout')), 'Timeout reason must be logged in receipt');
});
