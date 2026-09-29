const test = require('node:test');
const assert = require('node:assert');

const VeilRedactor = require('../extension/privacy/redactor.js');

test('Redactor Sync: didBoxesMove detects stationary vs moving elements', () => {
  const stationary1 = [
    { id: 'e1', bbox: [10, 20, 100, 30] },
    { id: 'e2', bbox: [50, 80, 200, 40] }
  ];
  const stationary2 = [
    { id: 'e1', bbox: [10.2, 20.1, 100.1, 29.9] },
    { id: 'e2', bbox: [50.0, 80.0, 200.0, 40.0] }
  ];

  // Within 1.0px tolerance -> no movement
  assert.strictEqual(VeilRedactor.didBoxesMove(stationary1, stationary2, 1.0), false);

  // Moved X by 5px -> motion detected
  const movedX = [
    { id: 'e1', bbox: [16, 20, 100, 30] },
    { id: 'e2', bbox: [50, 80, 200, 40] }
  ];
  assert.strictEqual(VeilRedactor.didBoxesMove(stationary1, movedX, 1.0), true);

  // Moved Y by 10px -> motion detected
  const movedY = [
    { id: 'e1', bbox: [10, 31, 100, 30] },
    { id: 'e2', bbox: [50, 80, 200, 40] }
  ];
  assert.strictEqual(VeilRedactor.didBoxesMove(stationary1, movedY, 1.0), true);

  // Box resized / transformed -> motion detected
  const resized = [
    { id: 'e1', bbox: [10, 20, 150, 30] },
    { id: 'e2', bbox: [50, 80, 200, 40] }
  ];
  assert.strictEqual(VeilRedactor.didBoxesMove(stationary1, resized, 1.0), true);

  // DOM node added/removed -> motion detected
  const countChanged = [{ id: 'e1', bbox: [10, 20, 100, 30] }];
  assert.strictEqual(VeilRedactor.didBoxesMove(stationary1, countChanged, 1.0), true);
});

test('Redactor Self-Check: verifyBoxBlack enforces solid black and fails closed on leak', () => {
  // Mock canvas 2D context
  function createMockCtx(pixelFn) {
    return {
      getImageData: (x, y, w, h) => {
        return { data: pixelFn(x, y) };
      }
    };
  }

  // 1. All pixels are solid black (R=0, G=0, B=0, A=255)
  const solidBlackCtx = createMockCtx((x, y) => new Uint8ClampedArray([0, 0, 0, 255]));
  const isSolid = VeilRedactor.verifyBoxBlack(solidBlackCtx, 10, 10, 50, 30);
  assert.strictEqual(isSolid, true, 'Solid black box must pass verification');

  // 2. Center pixel leaked white / text
  const centerLeakCtx = createMockCtx((x, y) => {
    if (x === 35 && y === 25) {
      return new Uint8ClampedArray([255, 255, 255, 255]); // Leaked white pixel
    }
    return new Uint8ClampedArray([0, 0, 0, 255]);
  });
  const failedCenter = VeilRedactor.verifyBoxBlack(centerLeakCtx, 10, 10, 50, 30);
  assert.strictEqual(failedCenter, false, 'Leaked white pixel must fail verification');

  // 3. Corner pixel leaked (translucent or partially masked)
  const cornerLeakCtx = createMockCtx((x, y) => {
    if (x === 10 && y === 10) {
      return new Uint8ClampedArray([0, 0, 0, 128]); // Transparent leak
    }
    return new Uint8ClampedArray([0, 0, 0, 255]);
  });
  const failedCorner = VeilRedactor.verifyBoxBlack(cornerLeakCtx, 10, 10, 50, 30);
  assert.strictEqual(failedCorner, false, 'Transparent/partially masked pixel must fail verification');
});

test('Redactor Sync Degradation: Motion or scroll during capture degrades to Strict mode', async () => {
  let callCount = 0;
  // Mock chrome.tabs API with scroll motion during capture
  globalThis.chrome = {
    tabs: {
      sendMessage: async (_tabId, msg) => {
        if (msg.type === 'GET_METRICS_AND_BOXES') {
          callCount++;
          // First reading scrollY = 0, second reading scrollY = 200 (user scrolled)
          return {
            scrollX: 0,
            scrollY: callCount % 2 === 1 ? 0 : 200,
            dpr: 1,
            viewport: [1280, 720],
            boxes: [{ id: 'e1', bbox: [10, 10, 100, 20] }]
          };
        }
      },
      captureVisibleTab: async () => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
    }
  };

  const res = await VeilRedactor.captureAndRedact(1, { nodes: [] });
  assert.strictEqual(res.redacted, false);
  assert.strictEqual(res.degraded, true);
  assert.strictEqual(res.image, null);
  assert.ok(res.reason.includes('Sync check failed'), `Expected sync check failure reason, got: ${res.reason}`);
});

test('Redactor Media and Sensitive Elements: Bounding box expansion and clipping math', () => {
  // Test 4px expansion & viewport clipping logic
  const viewportWidth = 1000;
  const viewportHeight = 800;

  function calculateRedactedBox(bbox) {
    let [x, y, w, h] = bbox;
    // Expand by 4px on all sides
    x = x - 4;
    y = y - 4;
    w = w + 8;
    h = h + 8;

    // Clip to viewport
    x = Math.max(0, x);
    y = Math.max(0, y);
    w = Math.min(viewportWidth - x, w);
    h = Math.min(viewportHeight - y, h);

    return [x, y, w, h];
  }

  // 1. Interior box: [50, 50, 100, 100] -> expands by 4px
  assert.deepStrictEqual(calculateRedactedBox([50, 50, 100, 100]), [46, 46, 108, 108]);

  // 2. Near top-left boundary: [2, 2, 50, 50] -> clipped at 0
  assert.deepStrictEqual(calculateRedactedBox([2, 2, 50, 50]), [0, 0, 58, 58]);

  // 3. Near bottom-right boundary: [980, 780, 50, 50] -> clipped to viewport
  assert.deepStrictEqual(calculateRedactedBox([980, 780, 50, 50]), [976, 776, 24, 24]);
});
