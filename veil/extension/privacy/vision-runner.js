// Vision Coordinator & Decision Engine for Veil Agent (Task 4, 5, 6, 7)
// Coordinates crop extraction, perceptual hashing, vision worker execution,
// fail-closed decision table, box mapping, and stage timing.

(() => {
  // In-memory volatile perceptual hash cache (never written to disk or storage)
  const cropVerdictCache = new Map();
  const MAX_CACHE_SIZE = 120;

  // Simple 64-bit difference hash (dHash) for fast crop perceptual hashing
  function computeCropDHash(pixels, width, height) {
    if (!pixels || width < 9 || height < 8) return '0';
    // Downsample to 9x8 grayscale
    const sampleW = 9;
    const sampleH = 8;
    const xStep = Math.floor(width / sampleW);
    const yStep = Math.floor(height / sampleH);

    const grays = new Uint8Array(sampleW * sampleH);
    for (let y = 0; y < sampleH; y++) {
      for (let x = 0; x < sampleW; x++) {
        const pxIdx = (y * yStep * width + x * xStep) * 4;
        const r = pixels[pxIdx];
        const g = pixels[pxIdx + 1];
        const b = pixels[pxIdx + 2];
        grays[y * sampleW + x] = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
      }
    }

    let hash = '';
    for (let y = 0; y < sampleH; y++) {
      for (let x = 0; x < sampleW - 1; x++) {
        const left = grays[y * sampleW + x];
        const right = grays[y * sampleW + x + 1];
        hash += left > right ? '1' : '0';
      }
    }
    return hash;
  }

  /**
   * Evaluates all media elements on the page using the vision worker
   * @param {CanvasRenderingContext2D} ctx - Context of original screenshot canvas
   * @param {Array} mediaNodes - List of media and sensitive nodes from DOM capture
   * @param {Object} options - { timeoutMs: 1500, visionEnabled: true, scaleX: 1, scaleY: 1 }
   * @returns {Promise<{
   *   boxesToRedact: Array,
   *   clearedMediaIds: Set,
   *   manifest: Array,
   *   metrics: Object
   * }>}
   */
  async function evaluateMediaWithVision(ctx, mediaNodes, options = {}) {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const timeoutMs = options.timeoutMs || 1500;
    const visionEnabled = options.visionEnabled !== false;
    const scaleX = options.scaleX || 1.0;
    const scaleY = options.scaleY || 1.0;

    const getTime = () => (typeof performance !== 'undefined' ? performance.now() : Date.now()) - startTime;

    const boxesToRedact = [];
    const clearedMediaIds = new Set();
    const manifest = [];
    const fallbackReasons = [];

    let facesCount = 0;
    let textRegionsCount = 0;
    let elementsCleared = 0;
    let elementsBlackedOut = 0;
    let cacheHits = 0;

    const worker = globalThis.VeilVisionWorker || (typeof require !== 'undefined' ? require('../workers/vision.worker.js') : null);
    let activeBackend = 'none';

    for (const node of mediaNodes) {
      const [x, y, w, h] = node.bbox;
      const tag = (node.tag || '').toLowerCase();
      const isCrossoriginIframe = tag === 'iframe' && node.crossorigin === true;

      // Invariant 10: Media stays fully black by default
      // Cross-origin iframes or nodes with existing PII stay black without un-blacking
      const hasPreExistingPii = Array.isArray(node.pii) && node.pii.length > 0;
      const isSensitiveField = node.sensitive === true && ['input', 'select', 'textarea'].includes(tag);

      if (!visionEnabled || !worker || isCrossoriginIframe || hasPreExistingPii || isSensitiveField || w <= 4 || h <= 4) {
        // Fall back closed to solid black for the entire element
        const type = isSensitiveField ? 'sensitive_input' : hasPreExistingPii ? `pii_${node.pii.join('_')}` : `media_${tag}`;
        boxesToRedact.push({ id: node.id, type, bbox: node.bbox, fullElement: true });
        elementsBlackedOut++;
        if (isCrossoriginIframe) fallbackReasons.push(`${node.id}: cross-origin iframe`);
        continue;
      }

      // Check time budget (Invariant 11: on timeout, region stays black)
      const elapsed = getTime();
      if (elapsed > timeoutMs) {
        boxesToRedact.push({ id: node.id, type: `media_${tag}`, bbox: node.bbox, fullElement: true });
        elementsBlackedOut++;
        fallbackReasons.push(`${node.id}: vision timeout (${Math.round(elapsed)}ms > ${timeoutMs}ms)`);
        continue;
      }

      try {
        // 1. Extract crop pixels from canvas
        const sx = Math.max(0, Math.round(x * scaleX));
        const sy = Math.max(0, Math.round(y * scaleY));
        const sw = Math.min(ctx.canvas.width - sx, Math.round(w * scaleX));
        const sh = Math.min(ctx.canvas.height - sy, Math.round(h * scaleY));

        if (sw <= 4 || sh <= 4) {
          boxesToRedact.push({ id: node.id, type: `media_${tag}`, bbox: node.bbox, fullElement: true });
          elementsBlackedOut++;
          continue;
        }

        const cropImgData = ctx.getImageData(sx, sy, sw, sh);
        const dHash = computeCropDHash(cropImgData.data, sw, sh);

        let verdict = null;

        // 2. Check perceptual cache (Task 7)
        if (cropVerdictCache.has(dHash)) {
          verdict = cropVerdictCache.get(dHash);
          cacheHits++;
        } else {
          // 3. Run Vision Worker
          const remainingBudget = Math.max(100, timeoutMs - getTime());
          verdict = await worker.detect(
            { data: cropImgData.data, width: sw, height: sh },
            { timeoutMs: remainingBudget }
          );

          activeBackend = verdict.backend || activeBackend;

          // Store in volatile memory cache
          if (cropVerdictCache.size >= MAX_CACHE_SIZE) {
            const firstKey = cropVerdictCache.keys().next().value;
            cropVerdictCache.delete(firstKey);
          }
          cropVerdictCache.set(dHash, verdict);
        }

        // 4. Decision Table (Task 6)
        // Rule: Vision failure, timeout, missing model, uncertainty, or ID appearance => stays black (fail closed)
        if (verdict.timeout || verdict.uncertain || verdict.error || verdict.cropLooksLikeId) {
          boxesToRedact.push({ id: node.id, type: `media_${tag}`, bbox: node.bbox, fullElement: true });
          elementsBlackedOut++;
          const reason = verdict.timeout ? 'timeout' : verdict.cropLooksLikeId ? 'document/ID layout' : verdict.error || 'uncertain';
          fallbackReasons.push(`${node.id}: ${reason}`);
          continue;
        }

        const detectedFaces = verdict.faces || [];
        const detectedWords = verdict.words || [];

        facesCount += detectedFaces.length;
        textRegionsCount += detectedWords.length;

        if (detectedFaces.length === 0 && detectedWords.length === 0) {
          // Vision ran successfully and found NOTHING uncertain or sensitive -> safely un-black!
          clearedMediaIds.add(node.id);
          elementsCleared++;
        } else {
          // Sensitive regions found -> black just those specific regions
          for (let fIdx = 0; fIdx < detectedFaces.length; fIdx++) {
            const f = detectedFaces[fIdx];
            // Map crop coordinates back to viewport coordinates
            const [cx, cy, cw, ch] = f.box;
            const vx = Math.round(x + cx / scaleX);
            const vy = Math.round(y + cy / scaleY);
            const vw = Math.round(cw / scaleX);
            const vh = Math.round(ch / scaleY);

            boxesToRedact.push({
              id: `${node.id}_face_${fIdx}`,
              parentId: node.id,
              type: 'face',
              bbox: [vx, vy, vw, vh]
            });
          }

          for (let wIdx = 0; wIdx < detectedWords.length; wIdx++) {
            const wb = detectedWords[wIdx];
            const [cx, cy, cw, ch] = wb.box;
            const vx = Math.round(x + cx / scaleX);
            const vy = Math.round(y + cy / scaleY);
            const vw = Math.round(cw / scaleX);
            const vh = Math.round(ch / scaleY);

            boxesToRedact.push({
              id: `${node.id}_ocr_${wIdx}`,
              parentId: node.id,
              type: 'pii_ocr_text',
              bbox: [vx, vy, vw, vh]
            });
          }
          clearedMediaIds.add(node.id); // Parent element media is visible except for the blacked-out face/PII boxes
        }
      } catch (err) {
        // Exception => fail closed, keep whole element black
        boxesToRedact.push({ id: node.id, type: `media_${tag}`, bbox: node.bbox, fullElement: true });
        elementsBlackedOut++;
        fallbackReasons.push(`${node.id}: exception (${err.message})`);
      }
    }

    const totalVisionMs = Math.round(getTime());

    return {
      boxesToRedact,
      clearedMediaIds,
      manifest,
      metrics: {
        totalVisionMs,
        backend: activeBackend,
        elementsProcessed: mediaNodes.length,
        elementsCleared,
        elementsBlackedOut,
        facesCount,
        textRegionsCount,
        cacheHits,
        fallbackReasons
      }
    };
  }

  // --- DOM-Vision Fusion & Visual-Only Node Handling (Phase 5, Task 4) ---
  function computeBoxIoU(b1, b2) {
    if (!b1 || !b2 || b1.length < 4 || b2.length < 4) return 0;
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

  function fuseDomAndVisualDetections(domNodes = [], detections = [], viewport = [1280, 800], redactionManifest = []) {
    const matchedDomIds = new Set();
    const visualOnlyNodes = [];
    let voCounter = 1;

    // Interactive DOM nodes filter
    const interactiveNodes = domNodes.filter((n) => {
      const tag = (n.tag || '').toLowerCase();
      const role = (n.role || '').toLowerCase();
      return (
        ['button', 'input', 'select', 'textarea', 'a'].includes(tag) ||
        ['button', 'link', 'textbox', 'combobox', 'checkbox', 'radio'].includes(role)
      );
    });

    for (const det of detections) {
      let bestIoU = 0;
      let bestNode = null;

      for (const node of domNodes) {
        if (!node.bbox || node.bbox.length < 4) continue;
        const iou = computeBoxIoU(det.box, node.bbox);
        if (iou > bestIoU) {
          bestIoU = iou;
          bestNode = node;
        }
      }

      if (bestIoU >= 0.30 && bestNode) {
        matchedDomIds.add(bestNode.id);
        bestNode.visual_match = {
          class: det.class,
          confidence: det.confidence,
          iou: Math.round(bestIoU * 100) / 100
        };
      } else {
        // Detections with no DOM node become "visual_only" nodes (vo1, vo2...)
        // Output schema: class + box only. Zero text.
        visualOnlyNodes.push({
          id: `vo${voCounter++}`,
          tag: det.class,
          role: 'visual_only',
          type: det.class,
          label: '',
          text: null,
          autocomplete: null,
          sensitive: false,
          bbox: det.box,
          confidence: det.confidence,
          pii: []
        });
      }
    }

    // Context accuracy = share of interactive DOM elements matched by a detection
    const matchedCount = interactiveNodes.filter((n) => matchedDomIds.has(n.id)).length;
    const contextAccuracy = interactiveNodes.length > 0 ? matchedCount / interactiveNodes.length : 1.0;

    return {
      fusedNodes: [...domNodes, ...visualOnlyNodes],
      visualOnlyNodes,
      matchedDomCount: matchedCount,
      totalInteractiveDomCount: interactiveNodes.length,
      contextAccuracy: Math.round(contextAccuracy * 1000) / 1000,
      detectionsCount: detections.length
    };
  }

  /**
   * Runs UI context detection strictly on already-redacted canvas
   * Degrades cleanly to DOM-only on missing model, timeout, or failure.
   */
  async function runUIContextDetection(redactedCanvasCtx, domNodes = [], options = {}) {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const getTime = () => (typeof performance !== 'undefined' ? performance.now() : Date.now()) - startTime;
    const timeoutMs = options.timeoutMs || 1500;
    const viewport = options.viewport || [1280, 800];
    const redactions = options.redactions || [];

    if (!redactedCanvasCtx || !redactedCanvasCtx.canvas) {
      return {
        fusedNodes: domNodes,
        visualOnlyNodes: [],
        degraded: true,
        reason: 'no_canvas',
        contextAccuracy: 1.0,
        ms: Math.round(getTime())
      };
    }

    const worker = globalThis.VeilVisionWorker || (typeof require !== 'undefined' ? require('../workers/vision.worker.js') : null);
    if (!worker || typeof worker.detectUI !== 'function') {
      return {
        fusedNodes: domNodes,
        visualOnlyNodes: [],
        degraded: true,
        reason: 'missing_worker',
        contextAccuracy: 1.0,
        ms: Math.round(getTime())
      };
    }

    try {
      const w = redactedCanvasCtx.canvas.width;
      const h = redactedCanvasCtx.canvas.height;
      const imgData = redactedCanvasCtx.getImageData(0, 0, w, h);

      const verdict = await worker.detectUI({ data: imgData.data, width: w, height: h }, { timeoutMs });

      if (verdict.degraded || verdict.timeout || verdict.error) {
        return {
          fusedNodes: domNodes,
          visualOnlyNodes: [],
          degraded: true,
          reason: verdict.error || 'timeout',
          contextAccuracy: 1.0,
          ms: Math.round(getTime())
        };
      }

      const fusionResult = fuseDomAndVisualDetections(domNodes, verdict.detections || [], viewport, redactions);
      return {
        ...fusionResult,
        degraded: false,
        ms: Math.round(getTime()),
        backend: verdict.backend
      };
    } catch (err) {
      // Invariant 15: Failure or timeout means "DOM only", never a crash
      return {
        fusedNodes: domNodes,
        visualOnlyNodes: [],
        degraded: true,
        reason: err.message,
        contextAccuracy: 1.0,
        ms: Math.round(getTime())
      };
    }
  }

  /**
   * Validates coordinate click targeting visual_only nodes (Invariant 16 & Task 4)
   */
  function validateVisualClick(action, targetNode, viewport = [1280, 800], redactionManifest = []) {
    if (!action) throw new Error('Action rejected: action payload is null or undefined');

    // 1. Typing into visual_only nodes is strictly forbidden
    if (action.action === 'type') {
      throw new Error('Action rejected: typing into visual_only nodes is strictly forbidden (Invariant 16)');
    }

    // 2. Only coordinate click is permitted
    if (action.action !== 'click') {
      throw new Error(`Action rejected: visual_only nodes may only be targeted by coordinate click, received '${action.action}'`);
    }

    if (!targetNode || !targetNode.bbox || targetNode.bbox.length < 4) {
      throw new Error(`Action rejected: visual_only node ${action.target_id} has invalid bounding box`);
    }

    // Determine target point [px, py]
    let px, py;
    if (Array.isArray(action.coords) && action.coords.length === 2) {
      [px, py] = action.coords;
    } else if (Array.isArray(action.point) && action.point.length === 2) {
      [px, py] = action.point;
    } else {
      // Default to center of bounding box if not explicitly specified
      px = Math.round(targetNode.bbox[0] + targetNode.bbox[2] / 2);
      py = Math.round(targetNode.bbox[1] + targetNode.bbox[3] / 2);
    }

    const [bx, by, bw, bh] = targetNode.bbox;

    // 3. Coordinate must be inside the detection bounding box
    if (px < bx || px > bx + bw || py < by || py > by + bh) {
      throw new Error(`Action rejected: coordinate click (${px}, ${py}) is outside bounding box [${targetNode.bbox.join(', ')}] of ${action.target_id}`);
    }

    // 4. Coordinate must be inside visible viewport
    const [vw, vh] = viewport;
    if (px < 0 || px > vw || py < 0 || py > vh) {
      throw new Error(`Action rejected: coordinate click (${px}, ${py}) is outside visible viewport [${vw}, ${vh}]`);
    }

    // 5. Coordinate must NOT intersect any redacted or sensitive region
    for (const r of redactionManifest) {
      if (!r.bbox || r.bbox.length < 4) continue;
      const [rx, ry, rw, rh] = r.bbox;
      if (px >= rx && px <= rx + rw && py >= ry && py <= ry + rh) {
        throw new Error(`Action rejected: coordinate click (${px}, ${py}) intersects redacted/sensitive region (${r.type || r.id})`);
      }
    }

    return { valid: true, coords: [px, py] };
  }

  function clearVerdictCache() {
    cropVerdictCache.clear();
  }

  const VeilVisionRunner = {
    evaluateMediaWithVision,
    computeCropDHash,
    clearVerdictCache,
    computeBoxIoU,
    fuseDomAndVisualDetections,
    runUIContextDetection,
    validateVisualClick
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilVisionRunner = VeilVisionRunner;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilVisionRunner;
  }
})();
