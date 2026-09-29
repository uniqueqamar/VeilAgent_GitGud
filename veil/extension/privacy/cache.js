// Change Detector and In-Memory Viewport Perceptual Hash Cache for Veil Agent (Task 6)
// Invariants:
// 1. Skips re-capture ONLY when: no DOM mutation, no scroll/resize, max age <= 3s, perceptual hash within threshold.
// 2. Memory-only: NEVER stored in IndexedDB or disk.
// 3. Discarded immediately on navigation or tab URL change.
// 4. Injected PII after caching causes DOM version bump and forces fresh redaction (never serves stale unredacted view).

(() => {
  const MAX_CACHE_AGE_MS = 3000; // 3 seconds max age
  const PHASH_HAMMING_THRESHOLD = 2; // Maximum bit difference for identical visual state

  let cachedEntry = null;
  let activeTabUrl = '';

  /**
   * Computes an 8x8 average perceptual hash (aHash) for a canvas context or pixel buffer.
   * Returns a 64-character binary string or hexadecimal string.
   */
  function computePerceptualHash(ctx, width, height) {
    if (!ctx || !width || !height) return '0'.repeat(64);

    try {
      // Sample 8x8 grid of luminance values
      const sampleW = 8;
      const sampleH = 8;
      const stepX = Math.floor(width / sampleW);
      const stepY = Math.floor(height / sampleH);
      const luminances = [];
      let sum = 0;

      for (let y = 0; y < sampleH; y++) {
        for (let x = 0; x < sampleW; x++) {
          const px = Math.min(width - 1, x * stepX + Math.floor(stepX / 2));
          const py = Math.min(height - 1, y * stepY + Math.floor(stepY / 2));
          const pixel = ctx.getImageData(px, py, 1, 1).data;
          // Relative luminance: 0.299*R + 0.587*G + 0.114*B
          const lum = Math.round(0.299 * pixel[0] + 0.587 * pixel[1] + 0.114 * pixel[2]);
          luminances.push(lum);
          sum += lum;
        }
      }

      const avg = sum / 64;
      let hash = '';
      for (let i = 0; i < 64; i++) {
        hash += luminances[i] >= avg ? '1' : '0';
      }
      return hash;
    } catch (_) {
      return '0'.repeat(64);
    }
  }

  /**
   * Computes Hamming distance (number of differing bits) between two binary hashes.
   */
  function hammingDistance(hash1, hash2) {
    if (!hash1 || !hash2 || hash1.length !== hash2.length) return 64;
    let dist = 0;
    for (let i = 0; i < hash1.length; i++) {
      if (hash1[i] !== hash2[i]) dist++;
    }
    return dist;
  }

  /**
   * Generates a cache key based on (scroll, zoom/DPR, DOM mutation version).
   */
  function getCacheKey(metrics) {
    const sx = metrics.scrollX || 0;
    const sy = metrics.scrollY || 0;
    const zoom = metrics.dpr || 1;
    const domVer = metrics.domVersion || 0;
    return `scroll:${sx},${sy}|zoom:${zoom}|domVer:${domVer}`;
  }

  /**
   * Checks whether the current page state can reuse the cached redacted screenshot.
   * @param {Object} currentMetrics - { scrollX, scrollY, dpr, domVersion, url, ctx, width, height }
   * @returns {{ canReuse: boolean, reason: string }}
   */
  function canReuseCache(currentMetrics) {
    if (!cachedEntry) {
      return { canReuse: false, reason: 'Cache empty' };
    }

    // 1. Navigation / Tab URL check: Discarded immediately on navigation
    if (currentMetrics.url && currentMetrics.url !== cachedEntry.url) {
      clearCache();
      return { canReuse: false, reason: 'Navigation detected: cache discarded' };
    }

    // 2. Max Age check: must not exceed 3 seconds
    const now = Date.now();
    const age = now - cachedEntry.timestamp;
    if (age > MAX_CACHE_AGE_MS) {
      clearCache();
      return { canReuse: false, reason: `Cache expired: age ${age}ms > ${MAX_CACHE_AGE_MS}ms` };
    }

    // 3. DOM Mutation check: Must have zero DOM mutations
    if (currentMetrics.domVersion !== cachedEntry.domVersion) {
      clearCache();
      return { canReuse: false, reason: 'DOM mutation detected: recapturing to scan new content' };
    }

    // 4. Scroll & Zoom check
    if (
      currentMetrics.scrollX !== cachedEntry.scrollX ||
      currentMetrics.scrollY !== cachedEntry.scrollY ||
      currentMetrics.dpr !== cachedEntry.dpr
    ) {
      clearCache();
      return { canReuse: false, reason: 'Viewport scroll or zoom changed' };
    }

    // 5. Perceptual hash check (if canvas context provided)
    if (currentMetrics.ctx && currentMetrics.width && currentMetrics.height) {
      const currentHash = computePerceptualHash(currentMetrics.ctx, currentMetrics.width, currentMetrics.height);
      const dist = hammingDistance(currentHash, cachedEntry.pHash);
      if (dist > PHASH_HAMMING_THRESHOLD) {
        clearCache();
        return { canReuse: false, reason: `Visual hash mismatch (Hamming distance ${dist} > ${PHASH_HAMMING_THRESHOLD})` };
      }
    }

    return { canReuse: true, reason: 'Valid in-memory cache hit' };
  }

  /**
   * Stores a redacted image in the volatile in-memory cache.
   */
  function storeCache(metrics, redactResult) {
    if (!redactResult || !redactResult.image || redactResult.degraded) {
      return;
    }

    let pHash = '0'.repeat(64);
    if (metrics.ctx && metrics.width && metrics.height) {
      pHash = computePerceptualHash(metrics.ctx, metrics.width, metrics.height);
    }

    cachedEntry = {
      timestamp: Date.now(),
      url: metrics.url || '',
      scrollX: metrics.scrollX || 0,
      scrollY: metrics.scrollY || 0,
      dpr: metrics.dpr || 1,
      domVersion: metrics.domVersion || 0,
      key: getCacheKey(metrics),
      pHash,
      image: redactResult.image,
      manifest: redactResult.manifest || [],
      clearedMediaIds: redactResult.clearedMediaIds || [],
      vision: redactResult.vision || null
    };
  }

  function getCachedResult() {
    if (!cachedEntry) return null;
    return {
      image: cachedEntry.image,
      manifest: cachedEntry.manifest,
      clearedMediaIds: cachedEntry.clearedMediaIds,
      vision: cachedEntry.vision,
      fromCache: true
    };
  }

  function clearCache() {
    cachedEntry = null;
  }

  const VeilRedactorCache = {
    computePerceptualHash,
    hammingDistance,
    getCacheKey,
    canReuseCache,
    storeCache,
    getCachedResult,
    clearCache,
    MAX_CACHE_AGE_MS,
    PHASH_HAMMING_THRESHOLD
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilRedactorCache = VeilRedactorCache;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilRedactorCache;
  }
})();
