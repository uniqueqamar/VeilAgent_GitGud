// Pure function lookalike-domain and context guard for Veil Agent (Task 4)
// Evaluates domains before vault credentials can be filled.
// Enforces:
// 1. HTTPS requirement (plain HTTP blocked, localhost/127.0.0.1 permitted for dev).
// 2. Punycode (xn--) and IDN mixed-script homograph attack detection (e.g. Cyrillic/Greek lookalikes).
// 3. Edit distance (Levenshtein) against user trusted list & small bundled gov/bank domain list.
// 4. Unknown domains require explicit user approval. Suspicious lookalikes are BLOCKED unconditionally.

(() => {
  // Small bundled, versioned list of top sensitive government and financial domains (v1.0)
  const BUNDLED_CRITICAL_DOMAINS = Object.freeze([
    'uidai.gov.in',
    'incometax.gov.in',
    'sbi.co.in',
    'hdfcbank.com',
    'icicibank.com',
    'axisbank.com',
    'digilocker.gov.in',
    'epfindia.gov.in',
    'paypal.com',
    'google.com'
  ]);

  // Unicode script ranges for homograph detection
  const CYRILLIC_REGEX = /[\u0400-\u04FF]/;
  const GREEK_REGEX = /[\u0370-\u03FF]/;
  const LATIN_REGEX = /[a-zA-Z]/;

  // Standard Levenshtein edit distance calculation
  function levenshteinDistance(s1, s2) {
    if (s1 === s2) return 0;
    if (s1.length === 0) return s2.length;
    if (s2.length === 0) return s1.length;

    const v0 = new Array(s2.length + 1);
    const v1 = new Array(s2.length + 1);

    for (let i = 0; i <= s2.length; i++) {
      v0[i] = i;
    }

    for (let i = 0; i < s1.length; i++) {
      v1[0] = i + 1;
      for (let j = 0; j < s2.length; j++) {
        const cost = s1[i] === s2[j] ? 0 : 1;
        v1[j + 1] = Math.min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost);
      }
      for (let j = 0; j <= s2.length; j++) {
        v0[j] = v1[j];
      }
    }

    return v1[s2.length];
  }

  // Extract base domain label for comparison (e.g. "sbi.co.in" -> "sbi", "paypal.com" -> "paypal")
  function extractMainBrand(hostname) {
    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    if (parts.length === 0) return '';
    if (parts.length === 1) return parts[0];
    // Special handling for two-part TLDs (e.g. .co.in, .gov.in, .ac.uk)
    const lastTwo = parts.slice(-2).join('.');
    if (lastTwo === 'co.in' || lastTwo === 'gov.in' || lastTwo === 'ac.in' || lastTwo === 'co.uk') {
      return parts.length >= 3 ? parts[parts.length - 3] : parts[0];
    }
    return parts[parts.length - 2];
  }

  /**
   * Pure domain validation function.
   * @param {string} urlOrHostname - Full URL or bare hostname
   * @param {Object} options - Options containing trustedSites, userApprovedSites, bundledDomains
   * @returns {{
   *   allowed: boolean,
   *   requiresApproval: boolean,
   *   isSuspicious: boolean,
   *   reason: string,
   *   hostname: string
   * }}
   */
  function validateDomain(urlOrHostname, options = {}) {
    if (!urlOrHostname || typeof urlOrHostname !== 'string') {
      return {
        allowed: false,
        requiresApproval: false,
        isSuspicious: true,
        reason: 'Empty or invalid domain',
        hostname: ''
      };
    }

    let protocol = 'https:';
    let hostname = urlOrHostname.trim().toLowerCase();

    // Parse protocol and hostname if full URL provided
    if (hostname.includes('://')) {
      try {
        const parsed = new URL(hostname);
        protocol = parsed.protocol;
        hostname = parsed.hostname.toLowerCase();
      } catch (_) {
        return {
          allowed: false,
          requiresApproval: false,
          isSuspicious: true,
          reason: 'Malformed URL',
          hostname
        };
      }
    }

    const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

    // 1. HTTPS Requirement (Localhost allowed for dev/tests)
    if (protocol !== 'https:' && !isLocalhost) {
      return {
        allowed: false,
        requiresApproval: false,
        isSuspicious: true,
        reason: 'HTTPS required: unencrypted plain HTTP blocked for credential protection',
        hostname
      };
    }

    if (isLocalhost) {
      return {
        allowed: true,
        requiresApproval: false,
        isSuspicious: false,
        reason: 'Localhost allowed for development/evaluation',
        hostname
      };
    }

    // 2. Punycode check
    const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');

    // 3. Mixed-Script / IDN Homograph check (e.g. Cyrillic "а" mixed with Latin)
    const hasLatin = LATIN_REGEX.test(hostname);
    const hasCyrillic = CYRILLIC_REGEX.test(hostname);
    const hasGreek = GREEK_REGEX.test(hostname);
    const isMixedScript = (hasLatin && hasCyrillic) || (hasLatin && hasGreek) || (hasCyrillic && hasGreek);

    if (isMixedScript) {
      return {
        allowed: false,
        requiresApproval: false,
        isSuspicious: true,
        reason: 'Blocked: IDN mixed-script homograph attack detected',
        hostname
      };
    }

    // Combine bundled and user-provided critical domains
    const bundled = options.bundledDomains || BUNDLED_CRITICAL_DOMAINS;
    const trustedSites = (options.trustedSites || []).map((s) => s.toLowerCase());
    const userApprovedSites = (options.userApprovedSites || []).map((s) => s.toLowerCase());

    const allProtectedDomains = [...new Set([...bundled, ...trustedSites])];

    // Check if hostname is an exact match in approved lists
    if (userApprovedSites.includes(hostname) || trustedSites.includes(hostname)) {
      if (hasPunycode) {
        return {
          allowed: false,
          requiresApproval: false,
          isSuspicious: true,
          reason: 'Blocked: Punycode encoded domain matching trusted site name',
          hostname
        };
      }
      return {
        allowed: true,
        requiresApproval: false,
        isSuspicious: false,
        reason: 'Domain approved in trusted list',
        hostname
      };
    }

    // 4. Lookalike / Typosquatting Check via Levenshtein Distance
    const targetBrand = extractMainBrand(hostname);

    for (const protectedDomain of allProtectedDomains) {
      const protectedBrand = extractMainBrand(protectedDomain);

      // (a) Exact brand match under different unfamiliar TLD (e.g. paypal.tk vs paypal.com)
      if (targetBrand === protectedBrand && hostname !== protectedDomain) {
        return {
          allowed: false,
          requiresApproval: false,
          isSuspicious: true,
          reason: `Blocked: lookalike domain copying trusted brand "${protectedBrand}" under different TLD`,
          hostname
        };
      }

      // (b) Levenshtein distance 1 or 2 on brand name (e.g. paypa1, sb1, uida1)
      const brandDist = levenshteinDistance(targetBrand, protectedBrand);
      if (brandDist > 0 && brandDist <= 2 && Math.min(targetBrand.length, protectedBrand.length) >= 3) {
        return {
          allowed: false,
          requiresApproval: false,
          isSuspicious: true,
          reason: `Blocked: typosquat lookalike domain (distance ${brandDist} to "${protectedDomain}")`,
          hostname
        };
      }

      // (c) Levenshtein distance on entire hostname
      const hostDist = levenshteinDistance(hostname, protectedDomain);
      if (hostDist > 0 && hostDist <= 2) {
        return {
          allowed: false,
          requiresApproval: false,
          isSuspicious: true,
          reason: `Blocked: typosquat lookalike domain (distance ${hostDist} to "${protectedDomain}")`,
          hostname
        };
      }

      // (d) Subdomain / host embedding of protected domain (e.g. sbi.co.in.fake.org or paypal.com.attacker.com)
      if (hostname.includes(protectedDomain) && hostname !== protectedDomain) {
        return {
          allowed: false,
          requiresApproval: false,
          isSuspicious: true,
          reason: `Blocked: lookalike domain embedding trusted domain "${protectedDomain}" in hostname`,
          hostname
        };
      }
    }

    // Punycode on unknown domain
    if (hasPunycode) {
      return {
        allowed: false,
        requiresApproval: false,
        isSuspicious: true,
        reason: 'Blocked: suspicious Punycode domain',
        hostname
      };
    }

    // 5. Normal new domain: Not suspicious, but requires user approval. Never auto-trust!
    return {
      allowed: false,
      requiresApproval: true,
      isSuspicious: false,
      reason: 'New domain: explicit user approval required before filling credentials',
      hostname
    };
  }

  const VeilDomainGuard = {
    validateDomain,
    levenshteinDistance,
    extractMainBrand,
    BUNDLED_CRITICAL_DOMAINS
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilDomainGuard = VeilDomainGuard;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilDomainGuard;
  }
})();
