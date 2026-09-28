// Local Encrypted Vault, Multi-Profile Schema and Session Tokenizer for Veil Agent
// Standalone script: WebCrypto (PBKDF2 + AES-GCM) with no external dependencies.
(() => {
  const subtle = globalThis.crypto?.subtle;
  const SCHEMA_VERSION = '1.0';

  function bytesToBase64(bytes) {
    let bin = '';
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) {
      bin += String.fromCharCode(arr[i]);
    }
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  // --- 1. WebCrypto PBKDF2 + AES-GCM Vault Encryption ---

  async function deriveKey(passphrase, saltBytes) {
    if (!subtle) throw new Error('WebCrypto subtle is not available');
    const enc = new TextEncoder();
    const keyMaterial = await subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptVault(vaultObj, passphrase) {
    if (!subtle) throw new Error('WebCrypto subtle is not available');
    if (!passphrase || typeof passphrase !== 'string') {
      throw new Error('Valid passphrase required for vault encryption');
    }

    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);

    const enc = new TextEncoder();
    const plaintext = enc.encode(JSON.stringify(vaultObj || {}));
    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      plaintext
    );

    return {
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext)
    };
  }

  async function decryptVault(encryptedRecord, passphrase) {
    if (!subtle) throw new Error('WebCrypto subtle is not available');
    if (!encryptedRecord?.salt || !encryptedRecord?.iv || !encryptedRecord?.ciphertext) {
      throw new Error('Invalid encrypted vault record');
    }
    if (!passphrase || typeof passphrase !== 'string') {
      throw new Error('Passphrase required for vault decryption');
    }

    const salt = base64ToBytes(encryptedRecord.salt);
    const iv = base64ToBytes(encryptedRecord.iv);
    const ciphertext = base64ToBytes(encryptedRecord.ciphertext);

    const key = await deriveKey(passphrase, salt);
    try {
      const decrypted = await subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
      );
      const dec = new TextDecoder();
      return JSON.parse(dec.decode(decrypted));
    } catch (e) {
      throw new Error('Failed to decrypt vault: invalid passphrase or corrupted data');
    }
  }

  // --- 2. Vault Schema, Sensitivity Classification & Multiple Profiles ---

  const SENSITIVITY_MAP = {
    // Low sensitivity (general demographic, location)
    GENDER: 'low',
    CATEGORY: 'low',
    STATE: 'low',
    CITY: 'low',
    DISTRICT: 'low',
    PIN: 'low',
    ADDRESS_LINE1: 'low',
    ADDRESS_LINE2: 'low',
    ADDRESS: 'low',

    // Medium sensitivity (direct contact and parent identifiers)
    FULL_NAME: 'medium',
    FIRST_NAME: 'medium',
    LAST_NAME: 'medium',
    EMAIL: 'medium',
    MOBILE: 'medium',
    MOBILE_CC: 'medium',
    MOBILE_PART1: 'medium',
    MOBILE_PART2: 'medium',
    FATHER_NAME: 'medium',
    MOTHER_NAME: 'medium',

    // High sensitivity (national IDs, banking, exact birthdate)
    DOB: 'high',
    DOB_DAY: 'high',
    DOB_MONTH: 'high',
    DOB_YEAR: 'high',
    AADHAAR: 'high',
    PAN: 'high',
    IFSC: 'high',
    ACCOUNT_NO: 'high'
  };

  const DEFAULT_PROFILES = {
    schema_version: SCHEMA_VERSION,
    active_profile: 'default',
    profiles: {
      default: {
        FULL_NAME: 'Asha Verma',
        FIRST_NAME: 'Asha',
        LAST_NAME: 'Verma',
        DOB: '1995-08-15',
        GENDER: 'Female',
        EMAIL: 'asha@example.com',
        MOBILE: '9876543210',
        ADDRESS_LINE1: 'Flat 402, Shanti Niketan',
        ADDRESS_LINE2: 'MG Road',
        CITY: 'Bangalore',
        DISTRICT: 'Bangalore Urban',
        STATE: 'Karnataka',
        PIN: '560001',
        FATHER_NAME: 'Ramesh Verma',
        MOTHER_NAME: 'Sunita Verma',
        CATEGORY: 'General',
        AADHAAR: '367598346012',
        PAN: 'ABCDE1234F',
        IFSC: 'SBIN0001234',
        ACCOUNT_NO: '12345678901'
      },
      parent: {
        FULL_NAME: 'Ramesh Verma',
        FIRST_NAME: 'Ramesh',
        LAST_NAME: 'Verma',
        DOB: '1965-04-12',
        GENDER: 'Male',
        EMAIL: 'ramesh.verma@example.com',
        MOBILE: '9876543211',
        ADDRESS_LINE1: 'Flat 402, Shanti Niketan',
        CITY: 'Bangalore',
        STATE: 'Karnataka',
        PIN: '560001',
        AADHAAR: '548792134560',
        PAN: 'PQRST5678G'
      }
    }
  };

  function getSensitivity(key) {
    if (!key || typeof key !== 'string') return 'medium';
    const norm = key.toUpperCase().trim();
    return SENSITIVITY_MAP[norm] || 'medium';
  }

  function isHighSensitivity(key) {
    return getSensitivity(key) === 'high';
  }

  function getProfile(vaultObj, profileName) {
    if (!vaultObj) return {};
    // Backward compatibility: flat vault structure
    if (!vaultObj.profiles) return vaultObj;
    const target = profileName || vaultObj.active_profile || 'default';
    return vaultObj.profiles[target] || vaultObj.profiles['default'] || {};
  }

  // Parse date into { year, month, day }
  function parseDateComponents(dateStr) {
    if (!dateStr || typeof dateStr !== 'string') return null;
    const s = dateStr.trim();
    let m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/);
    if (m) {
      return { year: m[1], month: m[2].padStart(2, '0'), day: m[3].padStart(2, '0') };
    }
    m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/);
    if (m) {
      return { day: m[1].padStart(2, '0'), month: m[2].padStart(2, '0'), year: m[3] };
    }
    return null;
  }

  // --- 3. Derived Value Compose Function (Task 1) ---

  function compose(key, profileData = {}, options = {}) {
    if (!key || typeof key !== 'string') return '';
    const normKey = key.toUpperCase().trim();
    const rawVal = profileData[normKey];

    // Split Date components
    if (normKey === 'DOB_DAY' || normKey === 'DOB_MONTH' || normKey === 'DOB_YEAR') {
      const parts = parseDateComponents(profileData.DOB);
      if (parts) {
        if (normKey === 'DOB_DAY') return parts.day;
        if (normKey === 'DOB_MONTH') return parts.month;
        if (normKey === 'DOB_YEAR') return parts.year;
      }
      return rawVal || '';
    }

    // Date formatting (DOB)
    if (normKey === 'DOB' || normKey.startsWith('DOB_')) {
      const parts = parseDateComponents(rawVal || profileData.DOB);
      if (parts) {
        let fmt = (options.format || 'YYYY-MM-DD').toUpperCase();
        if (normKey === 'DOB_DD_MM_YYYY') fmt = 'DD/MM/YYYY';
        if (normKey === 'DOB_DD_DASH_MM_YYYY' || normKey === 'DOB_DD-MM-YYYY') fmt = 'DD-MM-YYYY';
        if (normKey === 'DOB_MM_DD_YYYY') fmt = 'MM/DD/YYYY';
        if (fmt === 'DD/MM/YYYY') return `${parts.day}/${parts.month}/${parts.year}`;
        if (fmt === 'DD-MM-YYYY') return `${parts.day}-${parts.month}-${parts.year}`;
        if (fmt === 'MM/DD/YYYY') return `${parts.month}/${parts.day}/${parts.year}`;
        if (fmt === 'DD.MM.YYYY') return `${parts.day}.${parts.month}.${parts.year}`;
        return `${parts.year}-${parts.month}-${parts.day}`;
      }
      return rawVal || '';
    }

    // Name composition / decomposition
    if (normKey === 'FULL_NAME') {
      if (rawVal) return rawVal;
      const fn = profileData.FIRST_NAME || '';
      const ln = profileData.LAST_NAME || '';
      return `${fn} ${ln}`.trim();
    }

    if (normKey === 'FIRST_NAME') {
      if (rawVal) return rawVal;
      if (profileData.FULL_NAME) return profileData.FULL_NAME.split(' ')[0] || '';
      return '';
    }

    if (normKey === 'LAST_NAME') {
      if (rawVal) return rawVal;
      if (profileData.FULL_NAME) {
        const parts = profileData.FULL_NAME.split(' ');
        return parts.length > 1 ? parts.slice(1).join(' ') : '';
      }
      return '';
    }

    // Mobile split components
    if (normKey === 'MOBILE_CC') {
      return profileData.MOBILE_CC || '+91';
    }

    if (normKey === 'MOBILE_PART1' || normKey === 'MOBILE_PART2' || normKey === 'MOBILE_PART3') {
      const cleanPhone = (profileData.MOBILE || '').replace(/\D/g, '').slice(-10);
      if (cleanPhone.length === 10) {
        if (options.split === '3-3-4') {
          if (normKey === 'MOBILE_PART1') return cleanPhone.slice(0, 3);
          if (normKey === 'MOBILE_PART2') return cleanPhone.slice(3, 6);
          if (normKey === 'MOBILE_PART3') return cleanPhone.slice(6, 10);
        } else {
          // Default 5-5 split
          if (normKey === 'MOBILE_PART1') return cleanPhone.slice(0, 5);
          if (normKey === 'MOBILE_PART2') return cleanPhone.slice(5, 10);
        }
      }
      return rawVal || '';
    }

    // Combined address
    if (normKey === 'ADDRESS') {
      if (rawVal) return rawVal;
      const l1 = profileData.ADDRESS_LINE1 || '';
      const l2 = profileData.ADDRESS_LINE2 || '';
      return [l1, l2].filter(Boolean).join(', ');
    }

    return rawVal || '';
  }

  // Domain approval check for high sensitivity keys
  const _memoryDomainApprovals = {};

  function isKeyApprovedForDomain(arg1, arg2, domainApprovals = _memoryDomainApprovals) {
    let domain = arg1;
    let key = arg2;
    if (SENSITIVITY_MAP[arg1?.toUpperCase?.()] || (arg2?.includes?.('.') && !arg1?.includes?.('.'))) {
      key = arg1;
      domain = arg2;
    }
    if (!domain || !key) return false;
    const cleanDomain = domain.toLowerCase().trim();
    const approvedKeys = domainApprovals[cleanDomain] || [];
    return approvedKeys.includes(key.toUpperCase().trim());
  }

  function approveKeyForDomain(arg1, arg2, domainApprovals = _memoryDomainApprovals) {
    let domain = arg1;
    let key = arg2;
    if (SENSITIVITY_MAP[arg1?.toUpperCase?.()] || (arg2?.includes?.('.') && !arg1?.includes?.('.'))) {
      key = arg1;
      domain = arg2;
    }
    if (!domain || !key) return domainApprovals;
    const cleanDomain = domain.toLowerCase().trim();
    const normKey = key.toUpperCase().trim();
    const current = domainApprovals[cleanDomain] ? [...domainApprovals[cleanDomain]] : [];
    if (!current.includes(normKey)) {
      current.push(normKey);
    }
    domainApprovals[cleanDomain] = current;
    return domainApprovals;
  }

  // --- 4. Session Tokenizer & Masking ---

  function maskValue(val, type, showLast4 = false) {
    if (typeof val !== 'string') return 'XXXX';
    const clean = val.trim();
    if (!showLast4) {
      if (type === 'email') return 'XXXX@XXXX.XXX';
      if (type === 'aadhaar') return 'XXXX XXXX XXXX';
      if (type === 'card') return 'XXXX XXXX XXXX XXXX';
      if (type === 'mobile') return 'XXXXXXXXXX';
      if (type === 'pan') return 'XXXXXXXXXX';
      if (type === 'account_no') return 'XXXXXXXXXXXX';
      if (type === 'dob') return 'XXXX-XX-XX';
      return 'X'.repeat(Math.max(4, Math.min(clean.length, 16)));
    }

    // showLast4 === true
    const digitsOnly = clean.replace(/\D/g, '');
    if (digitsOnly.length >= 4) {
      const last4 = digitsOnly.slice(-4);
      if (type === 'aadhaar') return `XXXX XXXX ${last4}`;
      if (type === 'card') return `XXXX XXXX XXXX ${last4}`;
      if (type === 'mobile') return `XXXXXX${last4}`;
      if (type === 'account_no') return `XXXXXXX${last4}`;
    }
    if (clean.length > 4) {
      return 'X'.repeat(clean.length - 4) + clean.slice(-4);
    }
    return clean;
  }

  function createSessionTokenizer(options = {}) {
    const showLast4 = !!options.showLast4;
    const valueToToken = new Map();
    const tokenToValue = new Map();
    const typeCounters = new Map();

    function tokenize(value, type = 'VALUE') {
      if (typeof value !== 'string') return value;
      const cleanVal = value.trim();
      const normType = type.toUpperCase().replace(/[^A-Z0-9_]/g, '');

      if (valueToToken.has(cleanVal)) {
        return valueToToken.get(cleanVal);
      }

      const count = (typeCounters.get(normType) || 0) + 1;
      typeCounters.set(normType, count);
      const token = `[${normType}_${count}]`;

      valueToToken.set(cleanVal, token);
      tokenToValue.set(token, cleanVal);
      return token;
    }

    function resolve(token) {
      if (typeof token !== 'string') return null;
      const clean = token.trim();
      return tokenToValue.get(clean) ?? null;
    }

    function isSessionToken(token) {
      if (typeof token !== 'string') return false;
      return tokenToValue.has(token.trim());
    }

    function getIssuedTokens() {
      const out = {};
      for (const [token, val] of tokenToValue.entries()) {
        out[token] = {
          token,
          masked: maskValue(val, token.split('_')[0].replace('[', '').toLowerCase(), showLast4)
        };
      }
      return out;
    }

    function reset() {
      valueToToken.clear();
      tokenToValue.clear();
      typeCounters.clear();
    }

    return {
      tokenize,
      resolve,
      isSessionToken,
      mask: (val, type) => maskValue(val, type, showLast4),
      getIssuedTokens,
      reset
    };
  }

  const VeilVault = {
    SCHEMA_VERSION,
    SENSITIVITY_MAP,
    DEFAULT_PROFILES,
    encryptVault,
    decryptVault,
    maskValue,
    createSessionTokenizer,
    getSensitivity,
    isHighSensitivity,
    getProfile,
    compose,
    isKeyApprovedForDomain,
    approveKeyForDomain
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilVault = VeilVault;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilVault;
  }
})();
