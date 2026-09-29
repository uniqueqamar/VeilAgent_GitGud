// Pinned Model Loader & Integrity Verifier for Veil Agent (Task 2 & Invariant 12)
// This is the ONLY file besides privacy/gate.js permitted to make network calls,
// strictly limited to downloading pinned model files and validating their SHA-256 hashes.

(() => {
  const inMemoryModelCache = new Map();
  const CACHE_NAME = 'veil-models-v1';

  async function computeSha256(buffer) {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) throw new Error('WebCrypto subtle is required for SHA-256 verification');
    const digest = await subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function verifyModelBuffer(buffer, expectedHash) {
    if (!buffer || buffer.byteLength === 0) {
      throw new Error('Cannot verify empty model buffer');
    }
    const actualHash = await computeSha256(buffer);
    if (actualHash.toLowerCase() !== expectedHash.toLowerCase()) {
      throw new Error(
        `SECURITY VIOLATION: Model hash mismatch! Expected ${expectedHash}, got ${actualHash}. File may be corrupted or tampered.`
      );
    }
    return actualHash;
  }

  async function loadModel(modelId, manifest = null) {
    // 1. Check in-memory cache
    if (inMemoryModelCache.has(modelId)) {
      return inMemoryModelCache.get(modelId);
    }

    // 2. Load manifest
    let modelManifest = manifest;
    if (!modelManifest) {
      const api = globalThis.browser ?? globalThis.chrome;
      if (api?.runtime?.getURL) {
        try {
          const resp = await fetch(api.runtime.getURL('models/manifest.json'));
          modelManifest = await resp.json();
        } catch (_) {}
      }
      if (!modelManifest && typeof require !== 'undefined') {
        try {
          modelManifest = require('../models/manifest.json');
        } catch (_) {}
      }
    }

    const modelInfo = modelManifest?.models?.[modelId];
    if (!modelInfo) {
      throw new Error(`Model "${modelId}" not found in model manifest.`);
    }

    const { file, sha256: expectedHash, url: pinnedUrl } = modelInfo;
    let modelBuffer = null;

    // 3. Try loading from bundled extension assets
    const api = globalThis.browser ?? globalThis.chrome;
    if (api?.runtime?.getURL && file) {
      try {
        const localResp = await fetch(api.runtime.getURL(`models/${file}`));
        if (localResp.ok) {
          modelBuffer = await localResp.arrayBuffer();
        }
      } catch (_) {}
    }

    // 4. Try loading from Cache Storage (browser offline persistence)
    if (!modelBuffer && typeof caches !== 'undefined') {
      try {
        const cache = await caches.open(CACHE_NAME);
        const cachedResp = await cache.match(pinnedUrl);
        if (cachedResp) {
          modelBuffer = await cachedResp.arrayBuffer();
        }
      } catch (_) {}
    }

    // 5. Node filesystem fallback for test runners
    if (!modelBuffer && typeof require !== 'undefined') {
      try {
        const fs = require('fs');
        const path = require('path');
        const localPath = path.resolve(__dirname, '../models', file);
        if (fs.existsSync(localPath)) {
          const nodeBuf = fs.readFileSync(localPath);
          modelBuffer = nodeBuf.buffer.slice(nodeBuf.byteOffset, nodeBuf.byteOffset + nodeBuf.byteLength);
        }
      } catch (_) {}
    }

    // 6. Download from pinned URL (Invariant 12: only permitted network exception)
    if (!modelBuffer && pinnedUrl) {
      const resp = await fetch(pinnedUrl);
      if (!resp.ok) {
        throw new Error(`Failed to download model from pinned URL ${pinnedUrl} (status ${resp.status})`);
      }
      modelBuffer = await resp.arrayBuffer();

      // Verify before storing in Cache Storage
      await verifyModelBuffer(modelBuffer, expectedHash);

      if (typeof caches !== 'undefined') {
        try {
          const cache = await caches.open(CACHE_NAME);
          await cache.put(pinnedUrl, new Response(modelBuffer.slice(0)));
        } catch (_) {}
      }
    }

    if (!modelBuffer) {
      throw new Error(`Failed to load model "${modelId}": asset unavailable.`);
    }

    // 7. Verify integrity hash
    await verifyModelBuffer(modelBuffer, expectedHash);

    // Cache verified buffer in memory
    inMemoryModelCache.set(modelId, modelBuffer);
    return modelBuffer;
  }

  function clearMemoryCache() {
    inMemoryModelCache.clear();
  }

  const VeilModelLoader = {
    computeSha256,
    verifyModelBuffer,
    loadModel,
    clearMemoryCache
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilModelLoader = VeilModelLoader;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilModelLoader;
  }
})();
