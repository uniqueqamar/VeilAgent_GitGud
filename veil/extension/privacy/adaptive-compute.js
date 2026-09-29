// Adaptive Compute Engine for Veil Agent (Task 7)
// Probes hardwareConcurrency, deviceMemory and WebGPU to assign compute tiers.
// Invariants:
// 1. Lower tier means LESS vision (more solid black), NEVER less protection.
// 2. Sensitive inputs, PII detection and solid black masking hold equally across ALL tiers.
// 3. User can explicitly override the tier.

(() => {
  const TIERS = {
    HIGH: 'Tier 1 (High)',
    MEDIUM: 'Tier 2 (Medium)',
    LOW: 'Tier 3 (Low)'
  };

  /**
   * Probes device capabilities and returns a hardware profile.
   */
  async function probeDevice() {
    const nav = typeof navigator !== 'undefined' ? navigator : {};
    const concurrency = nav.hardwareConcurrency || 4;
    const memory = nav.deviceMemory || 4; // in GB
    let hasWebGPU = false;

    if (nav.gpu && typeof nav.gpu.requestAdapter === 'function') {
      try {
        const adapter = await nav.gpu.requestAdapter();
        hasWebGPU = !!adapter;
      } catch (_) {
        hasWebGPU = false;
      }
    }

    return {
      hardwareConcurrency: concurrency,
      deviceMemory: memory,
      hasWebGPU
    };
  }

  /**
   * Computes the recommended tier based on hardware capabilities.
   */
  function determineTier(profile) {
    const { hardwareConcurrency, deviceMemory, hasWebGPU } = profile;

    // High Tier: WebGPU available, or 8+ cores and 8GB+ RAM
    if (hasWebGPU || (hardwareConcurrency >= 8 && deviceMemory >= 8)) {
      return {
        tier: TIERS.HIGH,
        code: 'high',
        visionBackend: hasWebGPU ? 'webgpu' : 'wasm_simd',
        enableFaceDetection: true,
        enableOCRTextDetection: true,
        enableUIDetection: true,
        visionTimeoutMs: 1500,
        description: 'Full on-device vision pipeline with WebGPU/WASM acceleration'
      };
    }

    // Medium Tier: 4+ cores and 4GB+ RAM
    if (hardwareConcurrency >= 4 && deviceMemory >= 4) {
      return {
        tier: TIERS.MEDIUM,
        code: 'medium',
        visionBackend: 'wasm_simd',
        enableFaceDetection: true,
        enableOCRTextDetection: true,
        enableUIDetection: false, // UI detection degraded to save compute
        visionTimeoutMs: 1000,
        description: 'WASM SIMD vision enabled for faces and focused media regions'
      };
    }

    // Low Tier: Budget device / limited memory (< 4 cores or < 4GB)
    // Invariant: LESS vision (more black), never less protection!
    return {
      tier: TIERS.LOW,
      code: 'low',
      visionBackend: 'cpu_fallback',
      enableFaceDetection: false,     // Media stays solid black by default
      enableOCRTextDetection: false,  // Media stays solid black by default
      enableUIDetection: false,
      visionTimeoutMs: 500,
      description: 'Vision models bypassed; all media remains solid black (maximum safety, zero compute overhead)'
    };
  }

  /**
   * Resolves active compute configuration, respecting user override.
   */
  async function resolveComputeConfig(overrideTier = null) {
    const profile = await probeDevice();
    const autoTier = determineTier(profile);

    if (overrideTier && overrideTier !== 'Auto') {
      const code = overrideTier.toLowerCase();
      if (code.includes('high')) {
        return { ...determineTier({ hardwareConcurrency: 8, deviceMemory: 8, hasWebGPU: true }), isOverridden: true, profile };
      }
      if (code.includes('medium')) {
        return { ...determineTier({ hardwareConcurrency: 4, deviceMemory: 4, hasWebGPU: false }), isOverridden: true, profile };
      }
      if (code.includes('low')) {
        return { ...determineTier({ hardwareConcurrency: 2, deviceMemory: 2, hasWebGPU: false }), isOverridden: true, profile };
      }
    }

    return { ...autoTier, isOverridden: false, profile };
  }

  const VeilAdaptiveCompute = {
    TIERS,
    probeDevice,
    determineTier,
    resolveComputeConfig
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilAdaptiveCompute = VeilAdaptiveCompute;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilAdaptiveCompute;
  }
})();
