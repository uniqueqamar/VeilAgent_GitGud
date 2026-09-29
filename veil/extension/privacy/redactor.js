// Canvas Redactor for Veil Agent (Task 3)
// Performs secure viewport screenshot capture, sync check, expansion, scaling,
// solid black redaction of media and PII, self-check pixel sampling, and JPEG encoding.
// Runs in background script (Chrome service worker / Firefox event page).
(() => {
  const api = globalThis.browser ?? globalThis.chrome;

  function blobToBase64(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  }

  // Fallback for environments where FileReader is not available in worker
  async function blobToDataUrl(blob) {
    if (typeof FileReader !== 'undefined') {
      return blobToBase64(blob);
    }
    const buffer = await blob.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return 'data:image/jpeg;base64,' + btoa(bin);
  }

  // Check if boxes moved between measurements
  function didBoxesMove(boxes1, boxes2, tolerance = 1.0) {
    if (!boxes1 || !boxes2) return true;
    if (boxes1.length !== boxes2.length) return true;
    for (let i = 0; i < boxes1.length; i++) {
      const b1 = boxes1[i].bbox;
      const b2 = boxes2[i].bbox;
      if (
        Math.abs(b1[0] - b2[0]) > tolerance ||
        Math.abs(b1[1] - b2[1]) > tolerance ||
        Math.abs(b1[2] - b2[2]) > tolerance ||
        Math.abs(b1[3] - b2[3]) > tolerance
      ) {
        return true;
      }
    }
    return false;
  }

  // Self-check: sample pixels inside redacted box to guarantee solid black
  function verifyBoxBlack(ctx, sx, sy, sw, sh) {
    if (sw <= 0 || sh <= 0) return true;
    const sampleXs = [
      sx + Math.floor(sw / 2),
      sx,
      sx + sw - 1,
      sx + Math.floor(sw / 4),
      sx + Math.floor((3 * sw) / 4)
    ];
    const sampleYs = [
      sy + Math.floor(sh / 2),
      sy,
      sy + sh - 1,
      sy + Math.floor(sh / 4),
      sy + Math.floor((3 * sh) / 4)
    ];

    for (let i = 0; i < sampleXs.length; i++) {
      const px = Math.min(sx + sw - 1, Math.max(sx, sampleXs[i]));
      const py = Math.min(sy + sh - 1, Math.max(sy, sampleYs[i]));
      const pixel = ctx.getImageData(px, py, 1, 1).data;
      // R, G, B must be strictly 0, Alpha 255
      if (pixel[0] !== 0 || pixel[1] !== 0 || pixel[2] !== 0 || pixel[3] !== 255) {
        return false;
      }
    }
    return true;
  }

  function dataUrlToBlob(dataUrl) {
    const commaIdx = dataUrl.indexOf(',');
    const header = commaIdx >= 0 ? dataUrl.slice(0, commaIdx) : '';
    const mimeMatch = header.match(/:(.*?);/);
    const mime = mimeMatch ? mimeMatch[1] : 'image/png';
    const b64 = commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl;
    const bin = atob(b64);
    const len = bin.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new Blob([bytes], { type: mime });
  }

  /**
   * Main Redaction Pipeline
   * @param {number} tabId
   * @param {Object} domSnapshot
   * @returns {Promise<{image: string|null, original: string|null, redacted: boolean, manifest: Array, degraded: boolean, reason?: string}>}
   */
  async function captureAndRedact(tabId, domSnapshot, options = {}) {
    const api = globalThis.browser ?? globalThis.chrome;
    const MEDIA_TAGS = new Set(['img', 'canvas', 'video', 'svg', 'iframe', 'embed', 'object']);

    let rawScreenshotUrl = null;
    let bitmap = null;

    try {
      // 1. Sync check loop: retry up to twice if scroll or boxes moved
      let metrics1 = null;
      let metrics2 = null;
      let stable = false;

      for (let attempt = 0; attempt < 3; attempt++) {
        metrics1 = await api.tabs.sendMessage(tabId, { type: 'GET_METRICS_AND_BOXES' }).catch(() => null);
        if (!metrics1) break;

        // Take visible tab screenshot
        rawScreenshotUrl = await api.tabs.captureVisibleTab(null, { format: 'png' }).catch(() => null);
        if (!rawScreenshotUrl) break;

        // Re-read scroll, zoom, dpr, and boxes
        metrics2 = await api.tabs.sendMessage(tabId, { type: 'GET_METRICS_AND_BOXES' }).catch(() => null);
        if (!metrics2) break;

        const scrollMoved =
          Math.abs(metrics1.scrollY - metrics2.scrollY) > 1 ||
          Math.abs(metrics1.scrollX - metrics2.scrollX) > 1;
        const dprChanged = metrics1.dpr !== metrics2.dpr;
        const boxesMoved = didBoxesMove(metrics1.boxes, metrics2.boxes);

        if (!scrollMoved && !dprChanged && !boxesMoved) {
          stable = true;
          break;
        }

        // Wait briefly before retry
        await new Promise((r) => setTimeout(r, 60));
      }

      if (!stable || !rawScreenshotUrl) {
        // Degrade cleanly to Strict mode if motion detected or capture failed
        return {
          image: null,
          original: null,
          redacted: false,
          manifest: [],
          clearedMediaIds: [],
          vision: null,
          degraded: true,
          reason: 'Sync check failed: page scrolled or elements moved during capture'
        };
      }

      // 2. Decode screenshot to bitmap and draw on OffscreenCanvas (pure in-memory, no fetch)
      const rawOriginal = rawScreenshotUrl;
      const blob = dataUrlToBlob(rawScreenshotUrl);
      rawScreenshotUrl = null; // Dereference immediately

      bitmap = await createImageBitmap(blob);
      const width = bitmap.width;
      const height = bitmap.height;

      const canvas = new OffscreenCanvas(width, height);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(bitmap, 0, 0);

      // Close bitmap immediately after drawing
      bitmap.close();
      bitmap = null;

      const viewportWidth = metrics2.viewport ? metrics2.viewport[0] : (width / metrics2.dpr);
      const viewportHeight = metrics2.viewport ? metrics2.viewport[1] : (height / metrics2.dpr);
      const scaleX = width / viewportWidth;
      const scaleY = height / viewportHeight;

      // 3. Compile list of nodes to redact
      // Separate into media elements and sensitive/PII elements
      const manifest = [];
      const boxesToRedact = [];
      const clearedMediaIds = [];
      let visionMetrics = null;

      const nodes = domSnapshot?.nodes || metrics2.boxes || [];
      const mediaNodes = [];
      const sensitiveOrPiiNodes = [];

      for (const node of nodes) {
        const tag = (node.tag || '').toLowerCase();
        const isMedia = MEDIA_TAGS.has(tag) || node.hasBgImage || (node.role && node.role.startsWith('media'));
        const isSensitive = node.sensitive === true;
        const hasPii = Array.isArray(node.pii) && node.pii.length > 0;

        if (isSensitive || hasPii) {
          sensitiveOrPiiNodes.push(node);
        } else if (isMedia) {
          mediaNodes.push(node);
        }
      }

      // Vision coordinator evaluation (Task 6)
      const visionRunner = globalThis.VeilVisionRunner || (typeof require !== 'undefined' ? require('./vision-runner.js') : null);
      const useVision = options.visionEnabled !== false && visionRunner && typeof visionRunner.evaluateMediaWithVision === 'function';

      if (useVision && mediaNodes.length > 0) {
        const visionResult = await visionRunner.evaluateMediaWithVision(ctx, mediaNodes, {
          visionEnabled: true,
          scaleX,
          scaleY,
          timeoutMs: options.timeoutMs || 1500
        });

        if (Array.isArray(visionResult.boxesToRedact)) {
          for (const b of visionResult.boxesToRedact) {
            boxesToRedact.push(b);
          }
        }
        if (visionResult.clearedMediaIds) {
          for (const id of visionResult.clearedMediaIds) {
            clearedMediaIds.push(id);
          }
        }
        visionMetrics = visionResult.metrics || null;
      } else {
        // Fallback: all media nodes blacked out completely (fail closed)
        for (const mNode of mediaNodes) {
          const tag = (mNode.tag || '').toLowerCase();
          boxesToRedact.push({ id: mNode.id, type: `media_${tag}`, bbox: mNode.bbox, fullElement: true });
        }
      }

      // Add all sensitive and PII nodes (always solid black)
      for (const sNode of sensitiveOrPiiNodes) {
        const isSensitive = sNode.sensitive === true;
        const type = isSensitive ? 'sensitive_input' : `pii_${sNode.pii.join('_')}`;
        boxesToRedact.push({ id: sNode.id, type, bbox: sNode.bbox, fullElement: true });
      }

      // 4. Solid Black Fill with 4px expansion & viewport clipping
      ctx.fillStyle = '#000000';

      for (const item of boxesToRedact) {
        let [x, y, w, h] = item.bbox;

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

        if (w <= 0 || h <= 0) continue;

        // Scale by DPR / viewport ratio
        const sx = Math.round(x * scaleX);
        const sy = Math.round(y * scaleY);
        const sw = Math.round(w * scaleX);
        const sh = Math.round(h * scaleY);

        ctx.fillRect(sx, sy, sw, sh);

        // 5. Self-check: Sample pixels inside every redacted box (including vision boxes)
        const isBlack = verifyBoxBlack(ctx, sx, sy, sw, sh);
        if (!isBlack) {
          // Self-check failed closed
          return {
            image: null,
            original: null,
            redacted: false,
            manifest: [],
            clearedMediaIds: [],
            vision: visionMetrics,
            degraded: true,
            reason: `Self-check pixel sampling failed: box for ${item.id} was not solid black`
          };
        }

        const manifestEntry = {
          id: item.id,
          type: item.type,
          bbox: [sx, sy, sw, sh]
        };
        if (item.parentId) {
          manifestEntry.parentId = item.parentId;
        }
        manifest.push(manifestEntry);
      }

      // 6. Encode redacted canvas as JPEG (Open mode uses 0.95 full resolution quality)
      const jpegQuality = options.mode === 'Open' ? 0.95 : (options.quality || 0.85);
      const redactedBlob = await canvas.convertToBlob({ type: 'image/jpeg', quality: jpegQuality });
      const redactedBase64 = await blobToDataUrl(redactedBlob);

      return {
        image: redactedBase64,
        original: rawOriginal,
        canvasCtx: ctx, // Context of already-redacted canvas (Invariant 14)
        redacted: true,
        manifest,
        clearedMediaIds,
        vision: visionMetrics,
        degraded: false
      };
    } catch (err) {
      return {
        image: null,
        original: null,
        redacted: false,
        manifest: [],
        clearedMediaIds: [],
        vision: null,
        degraded: true,
        reason: `Redaction exception: ${err.message}`
      };
    } finally {
      if (bitmap) {
        try { bitmap.close(); } catch (_) {}
      }
    }
  }

  const VeilRedactor = {
    captureAndRedact,
    didBoxesMove,
    verifyBoxBlack
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilRedactor = VeilRedactor;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilRedactor;
  }
})();
