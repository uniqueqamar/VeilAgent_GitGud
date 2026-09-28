// PII Detection and Classification Worker for Veil Agent
// Standalone script: no external imports. Runs in browser and Node.js.
(() => {
  // Verhoeff algorithm tables for Aadhaar checksum validation
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ];

  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ];

  const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

  function validateVerhoeff(numStr) {
    if (!numStr || typeof numStr !== 'string') return false;
    let c = 0;
    const len = numStr.length;
    for (let i = 0; i < len; i++) {
      const digit = numStr.charCodeAt(len - 1 - i) - 48;
      if (digit < 0 || digit > 9) return false;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }
    return c === 0;
  }

  function validateLuhn(numStr) {
    if (!numStr || typeof numStr !== 'string') return false;
    let sum = 0;
    let alternate = false;
    for (let i = numStr.length - 1; i >= 0; i--) {
      const digit = numStr.charCodeAt(i) - 48;
      if (digit < 0 || digit > 9) return false;
      let n = digit;
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  // Devanagari digit normalization (०-९ -> 0-9)
  function normalizeDevanagari(text) {
    return text.replace(/[\u0966-\u096F]/g, (ch) =>
      String.fromCharCode(ch.charCodeAt(0) - 0x0966 + 48)
    );
  }

  // State code prefixes for Indian Driving Licence and Vehicle Plates
  const INDIAN_STATE_CODES = new Set([
    'AN', 'AP', 'AR', 'AS', 'BR', 'CH', 'CG', 'DD', 'DL', 'DN',
    'GA', 'GJ', 'HR', 'HP', 'JH', 'JK', 'KA', 'KL', 'LA', 'LD',
    'MH', 'ML', 'MN', 'MP', 'MZ', 'NL', 'OD', 'OR', 'PB', 'PY',
    'RJ', 'SK', 'TN', 'TR', 'TS', 'UA', 'UK', 'UP', 'WB'
  ]);

  // Common UPI provider handles
  const COMMON_UPI_PROVIDERS = new Set([
    'upi', 'okhdfcbank', 'oksbi', 'okaxis', 'okicici', 'paytm',
    'ybl', 'ibl', 'axl', 'postbank', 'barodampay', 'apl', 'federal',
    'indus', 'kotak', 'idfcbank', 'aubank', 'rbl', 'pingpay'
  ]);

  // Context keywords mapped to PII types
  const CONTEXT_KEYWORDS = {
    aadhaar: ['aadhaar', 'aadhar', 'uidai', 'uid', 'आधार'],
    pan: ['pan', 'incometax', 'nsdl', 'uti', 'tax id', 'पैन'],
    card: ['card', 'visa', 'mastercard', 'amex', 'rupay', 'cvv', 'cvc', 'credit', 'debit', 'कार्ड'],
    mobile: ['mobile', 'phone', 'cell', 'tel', 'whatsapp', 'call', 'contact', 'फ़ोन', 'मोबाइल'],
    email: ['email', 'e-mail', 'mail', 'ईमेल'],
    ifsc: ['ifsc', 'neft', 'rtgs', 'imps', 'bank', 'branch', 'बैंक'],
    upi: ['upi', 'vpa', 'bhim', 'pay'],
    passport: ['passport', 'travel doc', 'visa', 'पासपोर्ट'],
    voter_id: ['voter', 'epic', 'election', 'मतदाता'],
    driving_licence: ['dl', 'driving', 'licence', 'license', 'rto', 'ड्राइविंग'],
    plate: ['vehicle', 'registration', 'car', 'bike', 'motor', 'rc', 'plate', 'rto', 'गाड़ी']
  };

  function hasContextNear(text, start, end, type, windowSize = 60) {
    const keywords = CONTEXT_KEYWORDS[type];
    if (!keywords) return false;
    const lower = text.toLowerCase();
    const subStart = Math.max(0, start - windowSize);
    const subEnd = Math.min(lower.length, end + windowSize);
    const windowText = lower.slice(subStart, subEnd);
    return keywords.some((kw) => windowText.includes(kw));
  }

  // Detect PII in text
  function detectPII(rawText) {
    if (!rawText || typeof rawText !== 'string') return [];

    // ReDoS safety: Cap text at 5,000 characters
    const text = rawText.length > 5000 ? rawText.slice(0, 5000) : rawText;

    // Timeout safety: 50 ms budget
    const startTime = typeof performance !== 'undefined' && performance.now
      ? performance.now()
      : Date.now();
    const getTime = () =>
      (typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now()) - startTime;

    const normText = normalizeDevanagari(text);
    const findings = [];

    function addFinding(f) {
      if (f.start < 0 || f.end > text.length || f.start >= f.end) return;
      findings.push(f);
    }

    // 1. Email detection (Linear regex, non-nested quantifiers)
    const emailRegex = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,250}\.[A-Za-z]{2,12}\b/g;
    let m;
    while ((m = emailRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const matched = m[0];
      const cleanMatch = matched.replace(/\.+$/, '');
      const endPos = m.index + cleanMatch.length;
      addFinding({
        type: 'email',
        start: m.index,
        end: endPos,
        confidence: 0.98,
        value: text.slice(m.index, endPos)
      });
    }

    // 2. UPI ID detection (handle@provider, where provider has no email TLD or is known UPI provider)
    const upiRegex = /\b[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z0-9]{2,30}\b/g;
    while ((m = upiRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const val = m[0];
      const parts = val.split('@');
      if (parts.length === 2) {
        const provider = parts[1].toLowerCase();
        const hasDot = provider.includes('.');
        const isKnownProvider = COMMON_UPI_PROVIDERS.has(provider);
        const hasUpiContext = hasContextNear(normText, m.index, m.index + val.length, 'upi');
        if (isKnownProvider || (!hasDot && hasUpiContext) || (!hasDot && /upi|bank|pay|ok/i.test(provider))) {
          addFinding({
            type: 'upi',
            start: m.index,
            end: m.index + val.length,
            confidence: isKnownProvider || hasUpiContext ? 0.98 : 0.85,
            value: text.slice(m.index, m.index + val.length)
          });
        }
      }
    }

    // 3. Indian Mobile detection (+91, 91 or 0 prefix, 10 digits starting 6-9)
    // Accepts spaces or hyphens: +91 98765 43210, +91-9876543210, 919876543210, 09876543210, 9876543210
    const mobileRegex = /(?:\+?91[\s-]?)?(?:0[\s-]?)?[6-9](?:[\s-]?\d){9}\b/g;
    while ((m = mobileRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const raw = m[0];
      if (m.index > 0 && /\d/.test(normText[m.index - 1])) continue;
      const digitsOnly = raw.replace(/\D/g, '');
      const isMobile =
        (digitsOnly.length === 10 && /^[6-9]/.test(digitsOnly)) ||
        (digitsOnly.length === 11 && digitsOnly.startsWith('0') && /^[6-9]/.test(digitsOnly.slice(1))) ||
        (digitsOnly.length === 12 && digitsOnly.startsWith('91') && /^[6-9]/.test(digitsOnly.slice(2)));

      if (isMobile) {
        const hasCtx = hasContextNear(normText, m.index, m.index + raw.length, 'mobile');
        addFinding({
          type: 'mobile',
          start: m.index,
          end: m.index + raw.length,
          confidence: hasCtx ? 0.98 : 0.85,
          value: text.slice(m.index, m.index + raw.length)
        });
      }
    }

    // 4. Aadhaar detection (12 digits, first digit 2-9, Verhoeff checksum)
    const aadhaarRegex = /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g;
    while ((m = aadhaarRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const raw = m[0];
      const digitsOnly = raw.replace(/\D/g, '');
      if (digitsOnly.length === 12) {
        // Exclude all identical digits (e.g. 999999999999) which never represent real Aadhaar
        if (/^(\d)\1{11}$/.test(digitsOnly)) continue;

        // Enforce Verhoeff checksum: if invalid, must NEVER count as valid!
        if (validateVerhoeff(digitsOnly)) {
          const hasCtx = hasContextNear(normText, m.index, m.index + raw.length, 'aadhaar');
          addFinding({
            type: 'aadhaar',
            start: m.index,
            end: m.index + raw.length,
            confidence: hasCtx ? 0.99 : 0.90,
            value: text.slice(m.index, m.index + raw.length)
          });
        }
      }
    }

    // 5. Payment Card detection (13-19 digits, Luhn checksum)
    const cardRegex = /\b(?:\d[\s-]?){13,19}\b/g;
    while ((m = cardRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const raw = m[0];
      const digitsOnly = raw.replace(/\D/g, '');
      if (digitsOnly.length >= 13 && digitsOnly.length <= 19) {
        // Enforce Luhn: if invalid, must NEVER count as valid!
        if (validateLuhn(digitsOnly)) {
          const hasCtx = hasContextNear(normText, m.index, m.index + raw.length, 'card');
          addFinding({
            type: 'card',
            start: m.index,
            end: m.index + raw.length,
            confidence: hasCtx ? 0.99 : 0.85,
            value: text.slice(m.index, m.index + raw.length)
          });
        }
      }
    }

    // 6. PAN detection (5 uppercase letters, 4 digits, 1 uppercase letter)
    const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
    while ((m = panRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const val = m[0];
      // Check that it is not preceded by '0x' (hex number)
      if (m.index >= 2 && normText.slice(m.index - 2, m.index).toLowerCase() === '0x') continue;
      const entityChar = val[3];
      const validEntity = 'PCHFATBLJG'.includes(entityChar);
      const hasCtx = hasContextNear(normText, m.index, m.index + val.length, 'pan');
      if (validEntity || hasCtx) {
        addFinding({
          type: 'pan',
          start: m.index,
          end: m.index + val.length,
          confidence: hasCtx ? 0.99 : 0.90,
          value: text.slice(m.index, m.index + val.length)
        });
      }
    }

    // 7. IFSC detection (4 letters, '0', 6 alphanumeric)
    const ifscRegex = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;
    while ((m = ifscRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const val = m[0];
      const hasCtx = hasContextNear(normText, m.index, m.index + val.length, 'ifsc');
      addFinding({
        type: 'ifsc',
        start: m.index,
        end: m.index + val.length,
        confidence: hasCtx ? 0.99 : 0.90,
        value: text.slice(m.index, m.index + val.length)
      });
    }

    // 8. Passport detection (Indian: 1 letter A-PR-WYZ, 7 digits)
    const passportRegex = /\b[A-PR-WYZa-pr-wyz][1-9][0-9]{6}\b/g;
    while ((m = passportRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const val = m[0];
      const hasCtx = hasContextNear(normText, m.index, m.index + val.length, 'passport');
      addFinding({
        type: 'passport',
        start: m.index,
        end: m.index + val.length,
        confidence: hasCtx ? 0.98 : 0.80,
        value: text.slice(m.index, m.index + val.length)
      });
    }

    // 9. Voter ID / EPIC detection (3 letters, 7 digits)
    const voterRegex = /\b[A-Z]{3}[0-9]{7}\b/g;
    while ((m = voterRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const val = m[0];
      const hasCtx = hasContextNear(normText, m.index, m.index + val.length, 'voter_id');
      addFinding({
        type: 'voter_id',
        start: m.index,
        end: m.index + val.length,
        confidence: hasCtx ? 0.98 : 0.80,
        value: text.slice(m.index, m.index + val.length)
      });
    }

    // 10. Driving Licence detection
    const dlRegex = /\b([A-Z]{2})[\s-]?(0[1-9]|[1-9][0-9])[\s-]?(19\d\d|20\d\d)[\s-]?(\d{7})\b/g;
    while ((m = dlRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const state = m[1];
      if (INDIAN_STATE_CODES.has(state)) {
        const hasCtx = hasContextNear(normText, m.index, m.index + m[0].length, 'driving_licence');
        addFinding({
          type: 'driving_licence',
          start: m.index,
          end: m.index + m[0].length,
          confidence: hasCtx ? 0.99 : 0.88,
          value: text.slice(m.index, m.index + m[0].length)
        });
      }
    }

    // 11. Vehicle Plate detection
    const plateRegex = /\b(?:([A-Z]{2})[\s-]?(\d{1,2})[\s-]?([A-Z]{1,3})[\s-]?(\d{4})|(\d{2})[\s-]?(BH)[\s-]?(\d{4})[\s-]?([A-Z]{1,2}))\b/gi;
    while ((m = plateRegex.exec(normText)) !== null) {
      if (getTime() > 50) break;
      const state = (m[1] || '').toUpperCase();
      const isBH = !!m[6];
      if (INDIAN_STATE_CODES.has(state) || isBH) {
        const hasCtx = hasContextNear(normText, m.index, m.index + m[0].length, 'plate');
        addFinding({
          type: 'plate',
          start: m.index,
          end: m.index + m[0].length,
          confidence: hasCtx ? 0.98 : 0.85,
          value: text.slice(m.index, m.index + m[0].length)
        });
      }
    }

    // Deduplicate and resolve overlapping findings
    // Sort by start ascending, then length descending
    findings.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

    const resolved = [];
    let lastEnd = -1;
    for (const f of findings) {
      if (f.start >= lastEnd) {
        resolved.push(f);
        lastEnd = f.end;
      }
    }

    return resolved;
  }

  // Classify a form control or DOM node based on its attributes
  function classifyField(nodeInfo) {
    if (!nodeInfo || typeof nodeInfo !== 'object') {
      return { sensitive: false, pii_type: null };
    }

    const type = (nodeInfo.type || '').toLowerCase();
    const ac = (nodeInfo.autocomplete || '').toLowerCase();
    const name = (nodeInfo.name || '').toLowerCase();
    const id = (nodeInfo.id || '').toLowerCase();
    const label = (nodeInfo.label || '').toLowerCase();
    const placeholder = (nodeInfo.placeholder || '').toLowerCase();

    const allMeta = `${type} ${ac} ${name} ${id} ${label} ${placeholder}`;

    // 1. Password
    if (type === 'password' || /current-password|new-password/.test(ac) || /password|passwd|pwd/.test(name + ' ' + id)) {
      return { sensitive: true, pii_type: 'password' };
    }

    // 2. OTP / 2FA
    if (/one-time-code/.test(ac) || /otp|2fa|mfa|verification-?code|auth-?code/.test(allMeta)) {
      return { sensitive: true, pii_type: 'otp' };
    }

    // 3. Payment Card (number, CVV, expiry)
    if (
      /cc-number|cc-csc|cc-exp/.test(ac) ||
      /cvv|cvc|card[\s_-]?num|credit[\s_-]?card|debit[\s_-]?card|cc[\s_-]?num/.test(allMeta)
    ) {
      return { sensitive: true, pii_type: 'card' };
    }

    // 4. Aadhaar
    if (/aadhaar|aadhar|uidai/.test(allMeta)) {
      return { sensitive: true, pii_type: 'aadhaar' };
    }

    // 5. PAN
    if (/pan-?number|pan-?card|pancard/.test(allMeta)) {
      return { sensitive: true, pii_type: 'pan' };
    }

    // 6. Mobile / Phone
    if (type === 'tel' || /tel|mobile|phone|contact-?num/.test(allMeta)) {
      return { sensitive: false, pii_type: 'mobile' };
    }

    // 7. Email
    if (type === 'email' || /email|e-mail/.test(allMeta)) {
      return { sensitive: false, pii_type: 'email' };
    }

    // 8. Other sensitive identity documents
    if (/passport/.test(allMeta)) return { sensitive: true, pii_type: 'passport' };
    if (/voter|epic/.test(allMeta)) return { sensitive: true, pii_type: 'voter_id' };
    if (/driving-?licen[sc]e|license-?num/.test(allMeta)) return { sensitive: true, pii_type: 'driving_licence' };
    if (/ifsc/.test(allMeta)) return { sensitive: false, pii_type: 'ifsc' };
    if (/upi|vpa/.test(allMeta)) return { sensitive: false, pii_type: 'upi' };

    return { sensitive: false, pii_type: null };
  }

  const VeilPII = {
    detectPII,
    classifyField,
    validateVerhoeff,
    validateLuhn,
    normalizeDevanagari
  };

  // Cross-environment export (browser & Node.js)
  if (typeof globalThis !== 'undefined') {
    globalThis.VeilPII = VeilPII;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilPII;
  }
})();
