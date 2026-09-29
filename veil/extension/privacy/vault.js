// Local Encrypted Vault, Multi-Profile Schema and Session Tokenizer for Veil Agent
// Standalone script: WebCrypto (PBKDF2 + AES-GCM) with no external dependencies.
(() => {
  const subtle = globalThis.crypto?.subtle;
  const SCHEMA_VERSION = '2.0';

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

  // --- 2. Vault Schema, Sensitivity Classification & All Categories ---

  const SENSITIVE_KEYS = new Set([
    'PASSWORD',
    'AADHAAR',
    'PAN',
    'PASSPORT',
    'VOTER_ID',
    'DRIVING_LICENCE',
    'ACCOUNT_NO',
    'IFSC',
    'CARD_NUMBER',
    'CVV',
    'OTP'
  ]);

  const SENSITIVITY_MAP = {
    // Sensitive - ALWAYS SKIPPED on web forms for security & privacy
    PASSWORD: 'sensitive_skip',
    AADHAAR: 'sensitive_skip',
    PAN: 'sensitive_skip',
    PASSPORT: 'sensitive_skip',
    VOTER_ID: 'sensitive_skip',
    DRIVING_LICENCE: 'sensitive_skip',
    ACCOUNT_NO: 'sensitive_skip',
    IFSC: 'sensitive_skip',
    CARD_NUMBER: 'sensitive_skip',
    CVV: 'sensitive_skip',
    OTP: 'sensitive_skip',

    // Personal & Demographic
    FULL_NAME: 'medium',
    FIRST_NAME: 'medium',
    MIDDLE_NAME: 'medium',
    LAST_NAME: 'medium',
    DOB: 'medium',
    DOB_DAY: 'medium',
    DOB_MONTH: 'medium',
    DOB_YEAR: 'medium',
    GENDER: 'low',
    AGE: 'low',
    BLOOD_GROUP: 'low',
    MARITAL_STATUS: 'low',
    NATIONALITY: 'low',
    CATEGORY: 'low',
    FATHER_NAME: 'medium',
    MOTHER_NAME: 'medium',
    SPOUSE_NAME: 'medium',

    // Contact
    EMAIL: 'medium',
    ALT_EMAIL: 'medium',
    WORK_EMAIL: 'medium',
    MOBILE: 'medium',
    PHONE: 'medium',
    ALT_MOBILE: 'medium',
    WHATSAPP_NUMBER: 'medium',
    MOBILE_CC: 'low',

    // Current Address
    ADDRESS: 'low',
    CURRENT_ADDRESS: 'low',
    ADDRESS_LINE1: 'low',
    ADDRESS_LINE2: 'low',
    STREET_ADDRESS: 'low',
    LANDMARK: 'low',
    CITY: 'low',
    DISTRICT: 'low',
    STATE: 'low',
    PIN: 'low',
    ZIP: 'low',
    COUNTRY: 'low',

    // Permanent Address
    PERMANENT_ADDRESS: 'low',
    PERMANENT_ADDRESS_LINE1: 'low',
    PERMANENT_ADDRESS_LINE2: 'low',
    PERMANENT_CITY: 'low',
    PERMANENT_DISTRICT: 'low',
    PERMANENT_STATE: 'low',
    PERMANENT_PIN: 'low',
    PERMANENT_COUNTRY: 'low',

    // Education & Academics
    DEGREE: 'low',
    QUALIFICATION: 'low',
    MAJOR: 'low',
    STREAM: 'low',
    COLLEGE: 'low',
    UNIVERSITY: 'low',
    GRADUATION_YEAR: 'low',
    CGPA: 'low',
    PERCENTAGE: 'low',
    SCHOOL_12TH: 'low',
    SCHOOL_10TH: 'low',

    // Employment & Career
    JOB_TITLE: 'low',
    DESIGNATION: 'low',
    COMPANY: 'low',
    ORGANIZATION: 'low',
    EXPERIENCE_YEARS: 'low',
    ANNUAL_SALARY: 'medium',
    LINKEDIN_URL: 'low',
    GITHUB_URL: 'low',
    PORTFOLIO_URL: 'low',
    WEBSITE: 'low'
  };

  const DEFAULT_PROFILES = {
    schema_version: SCHEMA_VERSION,
    active_profile: 'default',
    profiles: {
      default: {
        // Personal
        FULL_NAME: 'Tanisha Choudhary',
        FIRST_NAME: 'Tanisha',
        MIDDLE_NAME: '',
        LAST_NAME: 'Choudhary',
        DOB: '2005-09-04',
        GENDER: 'Female',
        AGE: '19',
        BLOOD_GROUP: 'O+',
        MARITAL_STATUS: 'Single',
        NATIONALITY: 'Indian',
        CATEGORY: 'General',
        FATHER_NAME: 'Rajesh Choudhary',
        MOTHER_NAME: 'Sunita Choudhary',
        SPOUSE_NAME: '',

        // Contact
        EMAIL: 'tanishachoudhary090405@gmail.com',
        ALT_EMAIL: 'tanisha.alt@gmail.com',
        WORK_EMAIL: 'tanisha@work.com',
        MOBILE: '9876543210',
        ALT_MOBILE: '9876543211',
        WHATSAPP_NUMBER: '9876543210',
        MOBILE_CC: '+91',

        // Current Address
        ADDRESS_LINE1: 'Flat 402, Green Glen Heights, Outer Ring Road',
        ADDRESS_LINE2: 'Near Bellandur Junction',
        CITY: 'Bengaluru',
        DISTRICT: 'Bengaluru Urban',
        STATE: 'Karnataka',
        PIN: '560103',
        COUNTRY: 'India',

        // Permanent Address
        PERMANENT_ADDRESS_LINE1: 'Flat 402, Green Glen Heights, Outer Ring Road',
        PERMANENT_ADDRESS_LINE2: 'Near Bellandur Junction',
        PERMANENT_CITY: 'Bengaluru',
        PERMANENT_DISTRICT: 'Bengaluru Urban',
        PERMANENT_STATE: 'Karnataka',
        PERMANENT_PIN: '560103',
        PERMANENT_COUNTRY: 'India',

        // Education
        DEGREE: 'Bachelor of Technology (B.Tech)',
        MAJOR: 'Computer Science and Engineering',
        COLLEGE: 'National Institute of Technology',
        GRADUATION_YEAR: '2026',
        CGPA: '9.2',
        SCHOOL_12TH: 'Delhi Public School',
        SCHOOL_10TH: 'Delhi Public School',

        // Work
        JOB_TITLE: 'Software Engineer Intern',
        COMPANY: 'Tech Solutions Inc',
        EXPERIENCE_YEARS: '1',
        ANNUAL_SALARY: '800000',
        LINKEDIN_URL: 'https://linkedin.com/in/tanisha-choudhary',
        GITHUB_URL: 'https://github.com/tanisha-choudhary',
        PORTFOLIO_URL: 'https://tanisha.dev',

        // Sensitive (Saved securely in Vault, but ALWAYS SKIPPED during autofill)
        PASSWORD: 'ExamplePassword#2026',
        AADHAAR: '3675 9834 6012',
        PAN: 'ABCDE1234F',
        PASSPORT: '',
        VOTER_ID: '',
        DRIVING_LICENCE: '',
        ACCOUNT_NO: '',
        IFSC: ''
      }
    }
  };

  function isSensitive(key) {
    if (!key || typeof key !== 'string') return false;
    const norm = key.toUpperCase().trim();
    return SENSITIVE_KEYS.has(norm) || SENSITIVITY_MAP[norm] === 'sensitive_skip';
  }

  function getSensitivity(key) {
    if (!key || typeof key !== 'string') return 'medium';
    const norm = key.toUpperCase().trim();
    return SENSITIVITY_MAP[norm] || (SENSITIVE_KEYS.has(norm) ? 'sensitive_skip' : 'medium');
  }

  function isHighSensitivity(key) {
    return isSensitive(key);
  }

  function getProfile(vaultObj, profileName) {
    if (!vaultObj) return {};
    if (!vaultObj.profiles) return vaultObj;
    const target = profileName || vaultObj.active_profile || 'default';
    return vaultObj.profiles[target] || vaultObj.profiles['default'] || {};
  }

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

  // --- 3. Derived Value Compose Function ---

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
        return `${parts.year}-${parts.month}-${parts.day}`;
      }
      return rawVal || '';
    }

    // Name composition / decomposition
    if (normKey === 'FULL_NAME') {
      if (rawVal) return rawVal;
      const fn = profileData.FIRST_NAME || '';
      const mn = profileData.MIDDLE_NAME ? `${profileData.MIDDLE_NAME} ` : '';
      const ln = profileData.LAST_NAME || '';
      return `${fn} ${mn}${ln}`.trim();
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

    // Contact
    if (normKey === 'MOBILE' || normKey === 'PHONE') {
      return profileData.MOBILE || profileData.PHONE || profileData.WHATSAPP_NUMBER || '';
    }

    if (normKey === 'EMAIL') {
      return profileData.EMAIL || profileData.WORK_EMAIL || profileData.ALT_EMAIL || '';
    }

    // Address
    if (normKey === 'ADDRESS' || normKey === 'CURRENT_ADDRESS' || normKey === 'ADDRESS_LINE1' || normKey === 'STREET_ADDRESS') {
      if (profileData.ADDRESS_LINE1) {
        if (normKey === 'ADDRESS' || normKey === 'CURRENT_ADDRESS') {
          return [profileData.ADDRESS_LINE1, profileData.ADDRESS_LINE2].filter(Boolean).join(', ');
        }
        return profileData.ADDRESS_LINE1;
      }
      if (profileData.CURRENT_ADDRESS) return profileData.CURRENT_ADDRESS;
      if (profileData.ADDRESS) return profileData.ADDRESS;
      return rawVal || '';
    }

    if (normKey === 'PERMANENT_ADDRESS') {
      if (profileData.PERMANENT_ADDRESS) return profileData.PERMANENT_ADDRESS;
      return [profileData.PERMANENT_ADDRESS_LINE1, profileData.PERMANENT_ADDRESS_LINE2].filter(Boolean).join(', ') || profileData.ADDRESS_LINE1 || '';
    }

    // PIN / ZIP
    if (normKey === 'PIN' || normKey === 'ZIP' || normKey === 'PINCODE') {
      return profileData.PIN || profileData.ZIP || '';
    }

    // College / Degree / Company
    if (normKey === 'COLLEGE' || normKey === 'UNIVERSITY') {
      return profileData.COLLEGE || profileData.UNIVERSITY || '';
    }
    if (normKey === 'DEGREE' || normKey === 'QUALIFICATION') {
      return profileData.DEGREE || profileData.QUALIFICATION || '';
    }
    if (normKey === 'COMPANY' || normKey === 'ORGANIZATION') {
      return profileData.COMPANY || profileData.ORGANIZATION || '';
    }
    if (normKey === 'JOB_TITLE' || normKey === 'DESIGNATION') {
      return profileData.JOB_TITLE || profileData.DESIGNATION || '';
    }

    return rawVal || '';
  }

  // --- 4. Masking for Preview ---

  function maskValue(val, type) {
    if (typeof val !== 'string') return '••••';
    const clean = val.trim();
    if (!clean) return '';
    if (type === 'password') return '••••••••';
    if (type === 'aadhaar') return 'XXXX XXXX ' + (clean.replace(/\D/g, '').slice(-4) || 'XXXX');
    if (type === 'pan') return clean.slice(0, 2) + 'XXXXX' + clean.slice(-1);
    if (type === 'email') {
      const parts = clean.split('@');
      if (parts.length === 2) {
        return parts[0].slice(0, 2) + '•••@' + parts[1];
      }
    }
    if (clean.length > 8) {
      return clean.slice(0, 3) + '•••' + clean.slice(-3);
    }
    return clean;
  }

  const VeilVault = {
    SCHEMA_VERSION,
    SENSITIVE_KEYS,
    SENSITIVITY_MAP,
    DEFAULT_PROFILES,
    encryptVault,
    decryptVault,
    maskValue,
    getSensitivity,
    isSensitive,
    isHighSensitivity,
    getProfile,
    compose
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilVault = VeilVault;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilVault;
  }
})();
