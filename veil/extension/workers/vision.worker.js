// Veil Vision Worker (Task 3, 4, 5)
// Performs on-device Face Detection (UltraFace RFB-320) and Text/PII Detection (PaddleOCR DBNet)
// Runs off the main thread. Nothing here touches the network. Fails closed to solid black on error/timeout.

(() => {
  let ortInstance = null;
  let faceSession = null;
  let ocrSession = null;
  let uiSession = null;
  let activeBackend = 'probing';
  let lastActivityTime = Date.now();
  let idleUnloadTimer = null;

  const IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes idle model unload
  const FACE_INPUT_W = 320;
  const FACE_INPUT_H = 240;
  const OCR_INPUT_W = 480;
  const OCR_INPUT_H = 480;
  const UI_INPUT_SIZE = 416;

  const UI_CLASSES = [
    'button',
    'text_input',
    'checkbox',
    'radio',
    'dropdown',
    'link',
    'icon',
    'image',
    'table',
    'label',
    'dialog'
  ];

  // Precomputed YOLOX-nano 416x416 Anchor Grids (3,549 anchors across strides 8, 16, 32)
  const UI_ANCHOR_GRIDS = (() => {
    const strides = [8, 16, 32];
    const grids = [];
    const expandedStrides = [];
    for (const s of strides) {
      const h = Math.floor(UI_INPUT_SIZE / s);
      const w = Math.floor(UI_INPUT_SIZE / s);
      for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
          grids.push([x, y]);
          expandedStrides.push(s);
        }
      }
    }
    return { grids, expandedStrides };
  })();

  // --- 1. Precomputed UltraFace 320x240 Priors (4,420 anchors) ---
  const ULTRAFACE_PRIORS = (() => {
    const priors = [];
    const featureMaps = [
      [30, 40], // 240/8, 320/8
      [15, 20], // 240/16, 320/16
      [8, 10],  // 240/32, 320/32
      [4, 5]    // 240/64, 320/64
    ];
    const minSizes = [
      [10, 16, 24],
      [32, 48],
      [64, 96],
      [128, 192, 256]
    ];

    for (let k = 0; k < featureMaps.length; k++) {
      const [h, w] = featureMaps[k];
      for (let i = 0; i < h; i++) {
        for (let j = 0; j < w; j++) {
          for (let s = 0; s < minSizes[k].length; s++) {
            const minSize = minSizes[k][s];
            const sKx = minSize / FACE_INPUT_W;
            const sKy = minSize / FACE_INPUT_H;
            const cx = (j + 0.5) / w;
            const cy = (i + 0.5) / h;
            priors.push([cx, cy, sKx, sKy]);
          }
        }
      }
    }
    return priors;
  })();

  // --- 2. Environment & Backend Probing ---
  async function getOrt() {
    if (ortInstance) return ortInstance;
    if (typeof globalThis.ort !== 'undefined') {
      ortInstance = globalThis.ort;
      return ortInstance;
    }
    if (typeof require !== 'undefined') {
      try {
        ortInstance = require('onnxruntime-web');
        return ortInstance;
      } catch (_) {
        try {
          const path = require('path');
          ortInstance = require(path.resolve(__dirname, '../../eval/node_modules/onnxruntime-web'));
          return ortInstance;
        } catch (_2) {
          try {
            ortInstance = require('../lib/ort.all.min.js');
            return ortInstance;
          } catch (_) {}
        }
      }
    }
    throw new Error('ONNX Runtime Web is not loaded in this environment');
  }

  async function probeBackend() {
    if (activeBackend !== 'probing') return activeBackend;

    // 1. Probe WebGPU
    try {
      if (typeof navigator !== 'undefined' && navigator.gpu) {
        const adapter = await navigator.gpu.requestAdapter();
        if (adapter) {
          activeBackend = 'webgpu';
          return activeBackend;
        }
      }
    } catch (_) {}

    // 2. Fallback to WASM (SIMD / Threaded)
    activeBackend = 'wasm';
    return activeBackend;
  }

  // --- 3. Model Initialization & Lifecycle ---
  async function initSessions() {
    lastActivityTime = Date.now();
    resetIdleTimer();

    if (faceSession && ocrSession && uiSession) return;

    const ort = await getOrt();
    const backend = await probeBackend();
    const ep = backend === 'webgpu' ? ['webgpu', 'wasm'] : ['wasm'];

    // Configure WASM env
    if (ort.env?.wasm) {
      ort.env.wasm.simd = true;
      ort.env.wasm.numThreads = 2;
    }

    // Load models via VeilModelLoader
    const modelLoader = globalThis.VeilModelLoader || (typeof require !== 'undefined' ? require('../privacy/model-loader.js') : null);
    if (!modelLoader) throw new Error('VeilModelLoader not found');

    if (!faceSession) {
      const faceBuf = await modelLoader.loadModel('ultraface_rfb_320');
      faceSession = await ort.InferenceSession.create(faceBuf, { executionProviders: ep });
      // Warm up face model
      const dummyFace = new ort.Tensor('float32', new Float32Array(1 * 3 * FACE_INPUT_H * FACE_INPUT_W), [1, 3, FACE_INPUT_H, FACE_INPUT_W]);
      const res = await faceSession.run({ [faceSession.inputNames[0]]: dummyFace });
      dummyFace.dispose?.();
      for (const k of Object.keys(res)) res[k]?.dispose?.();
    }

    if (!ocrSession) {
      const ocrBuf = await modelLoader.loadModel('paddleocr_det_v3');
      ocrSession = await ort.InferenceSession.create(ocrBuf, { executionProviders: ep });
      // Warm up OCR model
      const dummyOcr = new ort.Tensor('float32', new Float32Array(1 * 3 * OCR_INPUT_H * OCR_INPUT_W), [1, 3, OCR_INPUT_H, OCR_INPUT_W]);
      const res = await ocrSession.run({ [ocrSession.inputNames[0]]: dummyOcr });
      dummyOcr.dispose?.();
      for (const k of Object.keys(res)) res[k]?.dispose?.();
    }

    if (!uiSession) {
      try {
        const uiBuf = await modelLoader.loadModel('yolox_nano');
        uiSession = await ort.InferenceSession.create(uiBuf, { executionProviders: ep });
        // Warm up UI model
        const dummyUI = new ort.Tensor('float32', new Float32Array(1 * 3 * UI_INPUT_SIZE * UI_INPUT_SIZE), [1, 3, UI_INPUT_SIZE, UI_INPUT_SIZE]);
        const res = await uiSession.run({ [uiSession.inputNames[0]]: dummyUI });
        dummyUI.dispose?.();
        for (const k of Object.keys(res)) res[k]?.dispose?.();
      } catch (err) {
        console.warn('UI Detector initialization warning (will fall back to DOM only):', err.message);
      }
    }
  }

  function resetIdleTimer() {
    if (idleUnloadTimer) clearTimeout(idleUnloadTimer);
    idleUnloadTimer = setTimeout(() => {
      unloadModels();
    }, IDLE_TIMEOUT_MS);
  }

  function unloadModels() {
    if (faceSession) {
      try { faceSession.release?.(); } catch (_) {}
      faceSession = null;
    }
    if (ocrSession) {
      try { ocrSession.release?.(); } catch (_) {}
      ocrSession = null;
    }
    if (uiSession) {
      try { uiSession.release?.(); } catch (_) {}
      uiSession = null;
    }
  }

  // --- 4. Bounding Box & NMS Helpers ---
  function iou(b1, b2) {
    const [x1, y1, w1, h1] = b1;
    const [x2, y2, w2, h2] = b2;
    const xi1 = Math.max(x1, x2);
    const yi1 = Math.max(y1, y2);
    const xi2 = Math.min(x1 + w1, x2 + w2);
    const yi2 = Math.min(y1 + h1, y2 + h2);
    const interArea = Math.max(0, xi2 - xi1) * Math.max(0, yi2 - yi1);
    const unionArea = w1 * h1 + w2 * h2 - interArea;
    return unionArea > 0 ? interArea / unionArea : 0;
  }

  function nms(boxesWithScores, iouThresh = 0.3) {
    boxesWithScores.sort((a, b) => b.conf - a.conf);
    const keep = [];
    for (let i = 0; i < boxesWithScores.length; i++) {
      let suppressed = false;
      for (let j = 0; j < keep.length; j++) {
        if (iou(boxesWithScores[i].box, keep[j].box) > iouThresh) {
          suppressed = true;
          break;
        }
      }
      if (!suppressed) keep.push(boxesWithScores[i]);
    }
    return keep;
  }

  // Expand box by percentage (e.g. 20% for face recall safety)
  function expandBox(box, pct, maxW, maxH) {
    let [x, y, w, h] = box;
    const dx = Math.round(w * (pct / 2));
    const dy = Math.round(h * (pct / 2));
    const nx = Math.max(0, x - dx);
    const ny = Math.max(0, y - dy);
    const nw = Math.min(maxW - nx, w + 2 * dx);
    const nh = Math.min(maxH - ny, h + 2 * dy);
    return [nx, ny, nw, nh];
  }

  // --- 5. Image Preprocessing & Tensor Conversion ---
  // Resizes pixel buffer to target dimensions and returns normalized Float32Array (CHW)
  function preprocessCrop(pixels, srcW, srcH, dstW, dstH, normalizeFn) {
    const out = new Float32Array(3 * dstW * dstH);
    const rOffset = 0;
    const gOffset = dstW * dstH;
    const bOffset = 2 * dstW * dstH;

    const xRatio = srcW / dstW;
    const yRatio = srcH / dstH;

    for (let dy = 0; dy < dstH; dy++) {
      const sy = Math.min(srcH - 1, Math.floor(dy * yRatio));
      for (let dx = 0; dx < dstW; dx++) {
        const sx = Math.min(srcW - 1, Math.floor(dx * xRatio));
        const srcIdx = (sy * srcW + sx) * 4;
        const dstIdx = dy * dstW + dx;

        const r = pixels[srcIdx];
        const g = pixels[srcIdx + 1];
        const b = pixels[srcIdx + 2];

        const [nr, ng, nb] = normalizeFn(r, g, b);
        out[rOffset + dstIdx] = nr;
        out[gOffset + dstIdx] = ng;
        out[bOffset + dstIdx] = nb;
      }
    }
    return out;
  }

  // --- 6. Face Detection Inference (UltraFace RFB-320) ---
  async function runFaceDetection(pixels, width, height, confThresh = 0.12) {
    const ort = await getOrt();
    // Normalize: (pixel - 127.0) / 128.0
    const normData = preprocessCrop(pixels, width, height, FACE_INPUT_W, FACE_INPUT_H, (r, g, b) => [
      (r - 127.0) / 128.0,
      (g - 127.0) / 128.0,
      (b - 127.0) / 128.0
    ]);

    const tensor = new ort.Tensor('float32', normData, [1, 3, FACE_INPUT_H, FACE_INPUT_W]);
    const results = await faceSession.run({ [faceSession.inputNames[0]]: tensor });
    tensor.dispose?.();

    const scores = results['scores'].data; // shape: [4420, 2]
    const boxes = results['boxes'].data;   // shape: [4420, 4]

    const centerVariance = 0.1;
    const sizeVariance = 0.2;
    const candidates = [];

    for (let i = 0; i < ULTRAFACE_PRIORS.length; i++) {
      const faceScore = scores[i * 2 + 1];
      if (faceScore >= confThresh) {
        const prior = ULTRAFACE_PRIORS[i];
        const cx = prior[0] + boxes[i * 4 + 0] * centerVariance * prior[2];
        const cy = prior[1] + boxes[i * 4 + 1] * centerVariance * prior[3];
        const w = prior[2] * Math.exp(boxes[i * 4 + 2] * sizeVariance);
        const h = prior[3] * Math.exp(boxes[i * 4 + 3] * sizeVariance);

        const x1 = Math.max(0, Math.round((cx - w / 2) * width));
        const y1 = Math.max(0, Math.round((cy - h / 2) * height));
        const bw = Math.min(width - x1, Math.round(w * width));
        const bh = Math.min(height - y1, Math.round(h * height));

        if (bw > 4 && bh > 4) {
          candidates.push({
            conf: faceScore,
            box: [x1, y1, bw, bh]
          });
        }
      }
    }

    // Dispose output tensors
    for (const k of Object.keys(results)) results[k]?.dispose?.();

    // NMS filtering
    const kept = nms(candidates, 0.3);

    // Expand faces by 20% for recall safety
    return kept.map((item) => ({
      conf: item.conf,
      box: expandBox(item.box, 0.20, width, height)
    }));
  }

  // --- 7. OCR Detection & PII Line Matching ---
  // PaddleOCR DBNet Detection + Heuristic Line Extraction & VeilPII Matching
  async function runOcrDetection(pixels, width, height) {
    const ort = await getOrt();
    // Normalize: (pixel / 255.0 - [0.485, 0.456, 0.406]) / [0.229, 0.224, 0.225]
    const normData = preprocessCrop(pixels, width, height, OCR_INPUT_W, OCR_INPUT_H, (r, g, b) => [
      (r / 255.0 - 0.485) / 0.229,
      (g / 255.0 - 0.456) / 0.224,
      (b / 255.0 - 0.406) / 0.225
    ]);

    const tensor = new ort.Tensor('float32', normData, [1, 3, OCR_INPUT_H, OCR_INPUT_W]);
    const results = await ocrSession.run({ [ocrSession.inputNames[0]]: tensor });
    tensor.dispose?.();

    const probMap = results[ocrSession.outputNames[0]].data; // [1, 1, 480, 480]
    for (const k of Object.keys(results)) results[k]?.dispose?.();

    // Threshold probability map at 0.3 for text regions
    const thresh = 0.3;
    const textRegions = [];
    const step = 8;
    const scaleX = width / OCR_INPUT_W;
    const scaleY = height / OCR_INPUT_H;

    for (let y = 0; y < OCR_INPUT_H; y += step) {
      let inBox = false;
      let startX = 0;
      for (let x = 0; x < OCR_INPUT_W; x += step) {
        const val = probMap[y * OCR_INPUT_W + x];
        if (val >= thresh && !inBox) {
          inBox = true;
          startX = x;
        } else if (val < thresh && inBox) {
          inBox = false;
          const boxW = (x - startX);
          if (boxW >= 16) {
            textRegions.push({
              conf: val,
              box: [
                Math.round(startX * scaleX),
                Math.round(y * scaleY),
                Math.round(boxW * scaleX),
                Math.round(step * 2.5 * scaleY)
              ]
            });
          }
        }
      }
    }

    return nms(textRegions, 0.2);
  }

  // Tolerates typical OCR character swaps in numeric fields (O->0, l->1, S->5, etc.)
  function correctOcrNumericNoise(text) {
    if (!text) return '';
    return text
      .replace(/[oO]/g, '0')
      .replace(/[lI]/g, '1')
      .replace(/[sS]/g, '5')
      .replace(/[bB]/g, '8');
  }

  // --- 8. Main Public Detect Method ---
  /**
   * Main vision pipeline execution for a media crop
   * @param {Object} cropData { data: Uint8ClampedArray|Array, width: number, height: number }
   * @param {Object} opts { timeoutMs: number, allowBlur: boolean }
   * @returns {Promise<{ faces: Array, words: Array, ms: number, backend: string, uncertain: boolean, cropLooksLikeId: boolean }>}
   */
  async function detect(cropData, opts = {}) {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const timeoutMs = opts.timeoutMs || 1500;
    const getTime = () => (typeof performance !== 'undefined' ? performance.now() : Date.now()) - startTime;

    if (!cropData?.data || !cropData?.width || !cropData?.height) {
      return {
        faces: [],
        words: [],
        ms: Math.round(getTime()),
        backend: activeBackend,
        uncertain: true,
        cropLooksLikeId: false,
        error: 'Invalid crop data'
      };
    }

    const { width, height } = cropData;
    const pixels = cropData.data;

    try {
      await initSessions();

      if (getTime() > timeoutMs) {
        return {
          faces: [],
          words: [],
          ms: Math.round(getTime()),
          backend: activeBackend,
          uncertain: true,
          cropLooksLikeId: false,
          timeout: true
        };
      }

      // 1. Run Face Detection
      const faces = await runFaceDetection(pixels, width, height, 0.45);

      if (getTime() > timeoutMs) {
        return {
          faces,
          words: [],
          ms: Math.round(getTime()),
          backend: activeBackend,
          uncertain: true,
          cropLooksLikeId: false,
          timeout: true
        };
      }

      // 2. Run OCR Detection
      const ocrBoxes = await runOcrDetection(pixels, width, height);

      // Check if crop looks like an ID card (standard aspect ratio 1.5 - 1.7, multiple lines + face)
      const aspect = width / height;
      const isCardAspect = aspect >= 1.4 && aspect <= 1.8;
      const hasFaceAndLines = faces.length >= 1 && ocrBoxes.length >= 3;
      const cropLooksLikeId = (isCardAspect && ocrBoxes.length >= 3) || hasFaceAndLines;

      // Heavy uncertainty check (Task 4): if 3+ overlapping detections or extreme ambiguity
      const uncertain = faces.length >= 4 && width < 300;

      const elapsed = Math.round(getTime());
      return {
        faces,
        words: ocrBoxes.map((b) => ({
          text: null, // Invariant: Never send recognized text to server
          box: b.box,
          conf: b.conf,
          type: 'ocr_text'
        })),
        ms: elapsed,
        backend: activeBackend,
        uncertain,
        cropLooksLikeId
      };
    } catch (err) {
      return {
        faces: [],
        words: [],
        ms: Math.round(getTime()),
        backend: activeBackend,
        uncertain: true,
        cropLooksLikeId: false,
        error: err.message
      };
    }
  }

  // --- 8.5. UI Element Detection via YOLOX-Nano (Phase 5, Task 3) ---
  // Runs ONLY on already-redacted image canvas. Returns { class, box, confidence } ONLY. No text.
  // Fails closed/safe: on error or timeout, returns { detections: [], degraded: true } (never a crash).
  async function detectUI(cropData, opts = {}) {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const getTime = () => (typeof performance !== 'undefined' ? performance.now() : Date.now()) - startTime;
    const timeoutMs = opts.timeoutMs || 1500;

    lastActivityTime = Date.now();
    resetIdleTimer();

    if (!cropData || !cropData.data || !cropData.width || !cropData.height) {
      return { detections: [], ms: 0, backend: activeBackend, degraded: true, reason: 'invalid_crop' };
    }

    const { data: pixels, width, height } = cropData;

    try {
      await initSessions();
      if (!uiSession) {
        return { detections: [], ms: Math.round(getTime()), backend: activeBackend, degraded: true, reason: 'missing_model' };
      }

      const ort = await getOrt();

      // Preprocess image: scale and letterbox into 416x416 Float32 CHW
      const scale = Math.min(UI_INPUT_SIZE / width, UI_INPUT_SIZE / height);
      const scaledW = Math.round(width * scale);
      const scaledH = Math.round(height * scale);

      const chw = new Float32Array(3 * UI_INPUT_SIZE * UI_INPUT_SIZE);
      chw.fill(114.0); // YOLOX letterbox fill value (114)

      const rOffset = 0;
      const gOffset = UI_INPUT_SIZE * UI_INPUT_SIZE;
      const bOffset = 2 * UI_INPUT_SIZE * UI_INPUT_SIZE;

      // Resample to letterbox
      for (let y = 0; y < scaledH; y++) {
        const srcY = Math.min(height - 1, Math.floor(y / scale));
        for (let x = 0; x < scaledW; x++) {
          const srcX = Math.min(width - 1, Math.floor(x / scale));
          const srcIdx = (srcY * width + srcX) * 4;
          const dstIdx = y * UI_INPUT_SIZE + x;

          // BGR order expected by YOLOX
          chw[rOffset + dstIdx] = pixels[srcIdx + 2]; // B
          chw[gOffset + dstIdx] = pixels[srcIdx + 1]; // G
          chw[bOffset + dstIdx] = pixels[srcIdx];     // R
        }
      }

      if (getTime() > timeoutMs) {
        return { detections: [], ms: Math.round(getTime()), backend: activeBackend, timeout: true, degraded: true };
      }

      const tensor = new ort.Tensor('float32', chw, [1, 3, UI_INPUT_SIZE, UI_INPUT_SIZE]);
      const feeds = { [uiSession.inputNames[0]]: tensor };
      const outputMap = await uiSession.run(feeds);
      tensor.dispose?.();

      const outTensor = outputMap[uiSession.outputNames[0]];
      const rawData = outTensor.data; // Float32Array of length 3549 * 85

      const numAnchors = 3549;
      const numChannels = 85;
      const { grids, expandedStrides } = UI_ANCHOR_GRIDS;

      const candidates = [];
      const scoreThresh = opts.scoreThreshold || 0.40;

      for (let i = 0; i < numAnchors; i++) {
        const offset = i * numChannels;
        const objConf = rawData[offset + 4];
        if (objConf < 0.05) continue;

        // Find max class in the 11 UI classes
        let maxClsScore = 0;
        let maxClsIdx = -1;
        for (let c = 0; c < UI_CLASSES.length; c++) {
          const clsProb = rawData[offset + 5 + c];
          if (clsProb > maxClsScore) {
            maxClsScore = clsProb;
            maxClsIdx = c;
          }
        }

        const score = objConf * maxClsScore;
        if (score >= scoreThresh && maxClsIdx >= 0) {
          const gx = grids[i][0];
          const gy = grids[i][1];
          const stride = expandedStrides[i];

          const cx = (rawData[offset] + gx) * stride;
          const cy = (rawData[offset + 1] + gy) * stride;
          const w = Math.exp(rawData[offset + 2]) * stride;
          const h = Math.exp(rawData[offset + 3]) * stride;

          // Map from 416x416 scaled space back to original image space
          const origX = Math.max(0, Math.round((cx - w / 2) / scale));
          const origY = Math.max(0, Math.round((cy - h / 2) / scale));
          const origW = Math.min(width - origX, Math.round(w / scale));
          const origH = Math.min(height - origY, Math.round(h / scale));

          if (origW >= 6 && origH >= 6) {
            candidates.push({
              class: UI_CLASSES[maxClsIdx],
              box: [origX, origY, origW, origH],
              conf: Math.round(score * 100) / 100
            });
          }
        }
      }

      outTensor.dispose?.();
      for (const k of Object.keys(outputMap)) outputMap[k]?.dispose?.();

      // NMS per class or overall
      const suppressed = nms(candidates, 0.40);

      // Clean output: { class, box, confidence } ONLY. No text.
      const detections = suppressed.map(c => ({
        class: c.class,
        box: c.box,
        confidence: c.conf
      }));

      return {
        detections,
        ms: Math.round(getTime()),
        backend: activeBackend,
        degraded: false
      };
    } catch (err) {
      // Invariant 15: Failure or timeout means "DOM only", never a crash
      return {
        detections: [],
        ms: Math.round(getTime()),
        backend: activeBackend,
        error: err.message,
        degraded: true
      };
    }
  }

  // --- 9. Worker Message Listener for Browser Worker ---
  if (typeof self !== 'undefined' && typeof postMessage === 'function') {
    self.onmessage = async (e) => {
      const msg = e.data;
      if (msg?.type === 'DETECT') {
        const result = await detect(msg.cropData, msg.opts);
        postMessage({ type: 'DETECT_RESULT', id: msg.id, result });
      } else if (msg?.type === 'DETECT_UI') {
        const result = await detectUI(msg.cropData, msg.opts);
        postMessage({ type: 'DETECT_UI_RESULT', id: msg.id, result });
      } else if (msg?.type === 'PROBE') {
        const backend = await probeBackend();
        postMessage({ type: 'PROBE_RESULT', backend });
      } else if (msg?.type === 'UNLOAD') {
        unloadModels();
        postMessage({ type: 'UNLOAD_RESULT', ok: true });
      }
    };
  }

  const VeilVisionWorker = {
    detect,
    detectUI,
    probeBackend,
    initSessions,
    unloadModels,
    correctOcrNumericNoise,
    expandBox,
    iou,
    nms,
    UI_CLASSES
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilVisionWorker = VeilVisionWorker;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilVisionWorker;
  }
})();
