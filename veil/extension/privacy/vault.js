// Local Encrypted Vault and Session Tokenizer for Veil Agent
// Standalone script: WebCrypto (PBKDF2 + AES-GCM) with no external dependencies.
(() => {
  const subtle = globalThis.crypto?.subtle;

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

  // --- 2. Session Tokenizer & Masking ---

  function maskValue(val, type, showLast4 = false) {
    if (typeof val !== 'string') return 'XXXX';
    const clean = val.trim();
    if (!showLast4) {
      // Default: reveal nothing
      if (type === 'email') return 'XXXX@XXXX.XXX';
      if (type === 'aadhaar') return 'XXXX XXXX XXXX';
      if (type === 'card') return 'XXXX XXXX XXXX XXXX';
      if (type === 'mobile') return 'XXXXXXXXXX';
      return 'X'.repeat(Math.max(4, Math.min(clean.length, 16)));
    }

    // showLast4 === true
    const digitsOnly = clean.replace(/\D/g, '');
    if (digitsOnly.length >= 4) {
      const last4 = digitsOnly.slice(-4);
      if (type === 'aadhaar') return `XXXX XXXX ${last4}`;
      if (type === 'card') return `XXXX XXXX XXXX ${last4}`;
      if (type === 'mobile') return `XXXXXX${last4}`;
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
      valueToToken.clear;
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
    encryptVault,
    decryptVault,
    maskValue,
    createSessionTokenizer
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.VeilVault = VeilVault;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VeilVault;
  }
})();
