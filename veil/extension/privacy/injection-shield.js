// Heuristic Injection Shield for Veil Agent (Task 3)
// Defends against prompt injection via DOM content:
// 1. Strips zero-width and bidirectional override characters.
// 2. Heuristically detects instruction-like phrases, role tags, and base64 blobs.
// 3. Replaces suspect instruction sequences with [SUSPECT_TEXT] and notes in receipts.
// 4. Client validation remains the primary security guarantee (defense-in-depth).

(() => {
  // Unicode ranges:
  // Zero-width: \u200B (ZWSP), \u200C (ZWNJ), \u200D (ZWJ), \uFEFF (BOM), \u2060 (WJ)
  // Bidi-override: \u202A-\u202E (LRE, RLE, PDF, LRO, RLO), \u2066-\u2069 (LRI, RLI, FSI, PDI)
  // Directional marks: \u200E (LRM), \u200F (RLM), \u00AD (soft hyphen)
  const ZERO_WIDTH_AND_BIDI_REGEX = /[\u200B-\u200D\uFEFF\u2060\u202A-\u202E\u2066-\u2069\u200E\u200F\u00AD]/g;

  // Instruction-like phrases (case-insensitive)
  const INSTRUCTION_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior|above|existing)\s+(instructions|prompts|rules|commands|context)/i,
    /you\s+are\s+now\s+(a|an)?\s*[a-z0-9_\-\s]{2,30}/i,
    /system\s+prompt\s*(:|=|is)/i,
    /new\s+(system\s+)?instruction\s*(:|=|is)/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|safety)/i,
    /enter\s+(your\s+)?(password|passcode|secret|credentials|otp|pin|credit\s+card)/i,
    /forget\s+(your\s+)?(instructions|training|rules|prompt)/i,
    /act\s+as\s+(an\s+unrestricted|a\s+hacked|an\s+evil|dan|a\s+root)/i,
    /bypass\s+(safety|filters|rules|restrictions)/i
  ];

  // Role tags used in LLM chat formatting
  const ROLE_TAG_PATTERNS = [
    /<\/?(system|assistant|human|user|im_start|im_end|tool|function)[^>]*>/i,
    /\[\/?(system|assistant|inst|sys|\/inst)\]/i,
    /<<\/?sys>>/i,
    /\|im_start\||\|im_end\|/i
  ];

  // Long base64 blobs (40+ base64 characters, often used for smuggling binary / hidden scripts)
  const BASE64_BLOB_PATTERN = /\b[A-Za-z0-9+/]{40,}={0,2}\b/;

  function stripZeroWidthAndBidi(str) {
    if (!str || typeof str !== 'string') return '';
    return str.replace(ZERO_WIDTH_AND_BIDI_REGEX, '');
  }

  function detectInstructionText(str) {
    if (!str || typeof str !== 'string') return { isSuspect: false, matched: [] };
    const clean = stripZeroWidthAndBidi(str);
    const matched = [];

    for (const pat of INSTRUCTION_PATTERNS) {
      if (pat.test(clean)) {
        matched.push(`pattern:${pat.source}`);
      }
    }

    for (const pat of ROLE_TAG_PATTERNS) {
      if (pat.test(clean)) {
        matched.push(`role_tag:${pat.source}`);
      }
    }

    if (BASE64_BLOB_PATTERN.test(clean)) {
      matched.push('base64_blob');
    }

    return {
      isSuspect: matched.length > 0,
      matched
    };
  }

  function sanitizeText(str) {
    if (!str || typeof str !== 'string') {
      return { text: str || '', suspectCount: 0, matched: [] };
    }

    // 1. Strip zero-width & bidi-override characters
    let processed = stripZeroWidthAndBidi(str);
    const allMatches = [];
    let count = 0;

    // 2. Check and mask instruction phrases
    for (const pat of INSTRUCTION_PATTERNS) {
      if (pat.test(processed)) {
        allMatches.push(pat.source);
        processed = processed.replace(pat, () => {
          count++;
          return '[SUSPECT_TEXT]';
        });
      }
    }

    // 3. Check and mask role tags
    for (const pat of ROLE_TAG_PATTERNS) {
      if (pat.test(processed)) {
        allMatches.push(pat.source);
        processed = processed.replace(pat, () => {
          count++;
          return '[SUSPECT_TEXT]';
        });
      }
    }

    // 4. Check and mask base64 blobs
    if (BASE64_BLOB_PATTERN.test(processed)) {
      allMatches.push('base64_blob');
      processed = processed.replace(new RegExp(BASE64_BLOB_PATTERN, 'g'), () => {
        count++;
        return '[SUSPECT_TEXT]';
      });
    }

    return {
      text: processed,
      suspectCount: count,
      matched: allMatches
    };
  }

  const VeilInjectionShield = {
    stripZeroWidthAndBidi,
    detectInstructionText,
    sanitizeText
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilInjectionShield = VeilInjectionShield;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilInjectionShield;
  }
})();
