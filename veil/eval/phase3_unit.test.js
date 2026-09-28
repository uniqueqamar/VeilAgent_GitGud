const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

// Load VeilVault
const VeilVault = require('../extension/privacy/vault.js');

test('VeilVault: WebCrypto PBKDF2 + AES-GCM Round Trip Encryption', async () => {
  const secretData = {
    NAME: 'Asha Verma',
    EMAIL: 'asha@example.com',
    PHONE: '9876543210',
    AADHAAR: '2345 6789 0128'
  };
  const passphrase = 'my-ultra-secure-passphrase-2026';

  const encryptedRecord = await VeilVault.encryptVault(secretData, passphrase);
  assert.ok(encryptedRecord.salt, 'salt must exist');
  assert.ok(encryptedRecord.iv, 'iv must exist');
  assert.ok(encryptedRecord.ciphertext, 'ciphertext must exist');

  // Must not contain plaintext in base64 ciphertext
  const rawCipher = atob(encryptedRecord.ciphertext);
  assert.ok(!rawCipher.includes('Asha Verma'), 'Ciphertext must not contain plaintext name');
  assert.ok(!rawCipher.includes('asha@example.com'), 'Ciphertext must not contain plaintext email');

  // Decrypt with correct passphrase
  const decrypted = await VeilVault.decryptVault(encryptedRecord, passphrase);
  assert.deepStrictEqual(decrypted, secretData, 'Decrypted vault must match original plaintext');

  // Decrypt with wrong passphrase must fail
  await assert.rejects(
    async () => {
      await VeilVault.decryptVault(encryptedRecord, 'wrong-password');
    },
    /Failed to decrypt vault/,
    'Decryption with incorrect passphrase must throw error'
  );
});

test('VeilVault: Session Tokenizer and Masking', () => {
  const tokenizerDefault = VeilVault.createSessionTokenizer({ showLast4: false });

  // Typed token issuance
  const tEmail1 = tokenizerDefault.tokenize('asha@example.com', 'email');
  assert.strictEqual(tEmail1, '[EMAIL_1]');

  const tName1 = tokenizerDefault.tokenize('Asha Verma', 'name');
  assert.strictEqual(tName1, '[NAME_1]');

  const tPhone1 = tokenizerDefault.tokenize('9876543210', 'phone');
  assert.strictEqual(tPhone1, '[PHONE_1]');

  // Same value within a session receives identical token
  const tEmailRepeat = tokenizerDefault.tokenize('asha@example.com', 'email');
  assert.strictEqual(tEmailRepeat, '[EMAIL_1]', 'Same value must receive the same token in a session');

  const tNameRepeat = tokenizerDefault.tokenize('Asha Verma', 'name');
  assert.strictEqual(tNameRepeat, '[NAME_1]', 'Same value must receive the same token in a session');

  // Different value gets next sequential index
  const tEmail2 = tokenizerDefault.tokenize('bob@example.com', 'email');
  assert.strictEqual(tEmail2, '[EMAIL_2]');

  // Resolution
  assert.strictEqual(tokenizerDefault.resolve('[EMAIL_1]'), 'asha@example.com');
  assert.strictEqual(tokenizerDefault.resolve('[NAME_1]'), 'Asha Verma');
  assert.strictEqual(tokenizerDefault.resolve('[UNKNOWN_TOKEN]'), null);

  // isSessionToken
  assert.strictEqual(tokenizerDefault.isSessionToken('[EMAIL_1]'), true);
  assert.strictEqual(tokenizerDefault.isSessionToken('[EMAIL_99]'), false);
  assert.strictEqual(tokenizerDefault.isSessionToken('plain string'), false);

  // Default masks: reveal nothing
  assert.strictEqual(tokenizerDefault.mask('asha@example.com', 'email'), 'XXXX@XXXX.XXX');
  assert.strictEqual(tokenizerDefault.mask('2345 6789 0128', 'aadhaar'), 'XXXX XXXX XXXX');
  assert.strictEqual(tokenizerDefault.mask('4532 0151 1283 0366', 'card'), 'XXXX XXXX XXXX XXXX');
  assert.strictEqual(tokenizerDefault.mask('9876543210', 'mobile'), 'XXXXXXXXXX');

  // Tokenizer with showLast4: true
  const tokenizerLast4 = VeilVault.createSessionTokenizer({ showLast4: true });
  assert.strictEqual(tokenizerLast4.mask('2345 6789 0128', 'aadhaar'), 'XXXX XXXX 0128');
  assert.strictEqual(tokenizerLast4.mask('4532 0151 1283 0366', 'card'), 'XXXX XXXX XXXX 0366');
  assert.strictEqual(tokenizerLast4.mask('9876543210', 'mobile'), 'XXXXXX3210');
  assert.strictEqual(tokenizerLast4.mask('Asha Verma', 'name'), 'XXXXXXerma');
});

test('Placeholder Resolution: In-memory vault and token validation', async () => {
  const vault = {
    NAME: 'Asha Verma',
    EMAIL: 'asha@example.com',
    PHONE: '9876543210'
  };

  const tokenizer = VeilVault.createSessionTokenizer();
  tokenizer.tokenize(vault.NAME, 'name');
  tokenizer.tokenize(vault.EMAIL, 'email');
  tokenizer.tokenize(vault.PHONE, 'phone');

  function resolveValue(value, tabUrl) {
    if (value === null || value === undefined) return value;
    if (typeof value !== 'string') throw new Error('Value must be a string');

    const isPlainHttp = tabUrl && tabUrl.startsWith('http:') &&
      !tabUrl.startsWith('http://localhost') &&
      !tabUrl.startsWith('http://127.0.0.1');

    // 1. Session token
    if (tokenizer.isSessionToken(value)) {
      if (isPlainHttp) {
        throw new Error('Action rejected: refusing to fill identity fields on unencrypted http:// page');
      }
      return tokenizer.resolve(value);
    }

    // 2. Exact vault keys {{KEY}}
    const placeholderRegex = /\{\{([A-Z0-9_]+)\}\}/g;
    let match;
    let hasPlaceholder = false;
    while ((match = placeholderRegex.exec(value)) !== null) {
      hasPlaceholder = true;
      const key = match[1];
      if (!(key in vault)) {
        throw new Error(`Action rejected: unknown vault placeholder {{${key}}}`);
      }
    }

    if (hasPlaceholder) {
      if (isPlainHttp) {
        throw new Error('Action rejected: refusing to fill identity fields on unencrypted http:// page');
      }
      return value.replace(placeholderRegex, (_, k) => vault[k] ?? '');
    }

    // 3. Reject unknown tokens
    if (/^\[[A-Z0-9_]+\]$/.test(value.trim())) {
      throw new Error(`Action rejected: token ${value} was not issued in this session`);
    }

    return value;
  }

  // Valid resolutions
  assert.strictEqual(resolveValue('[NAME_1]', 'https://secure.example.com'), 'Asha Verma');
  assert.strictEqual(resolveValue('{{EMAIL}}', 'https://secure.example.com'), 'asha@example.com');
  assert.strictEqual(resolveValue('Hello {{NAME}}!', 'https://secure.example.com'), 'Hello Asha Verma!');

  // Rejection of unknown placeholder
  assert.throws(
    () => resolveValue('{{UNKNOWN_FIELD}}', 'https://secure.example.com'),
    /unknown vault placeholder \{\{UNKNOWN_FIELD\}\}/
  );

  // Rejection of non-session token (e.g. from page content or forged)
  assert.throws(
    () => resolveValue('[INJECTED_TOKEN_1]', 'https://secure.example.com'),
    /token \[INJECTED_TOKEN_1\] was not issued in this session/
  );

  // Rejection of identity fill on unencrypted remote http:// page
  assert.throws(
    () => resolveValue('[EMAIL_1]', 'http://insecure-bank.example.com/kyc'),
    /refusing to fill identity fields on unencrypted http:\/\/ page/
  );
  assert.throws(
    () => resolveValue('{{EMAIL}}', 'http://insecure-bank.example.com/kyc'),
    /refusing to fill identity fields on unencrypted http:\/\/ page/
  );

  // Allowed on localhost / 127.0.0.1 http
  assert.strictEqual(resolveValue('[NAME_1]', 'http://localhost:8000/kyc'), 'Asha Verma');
  assert.strictEqual(resolveValue('{{EMAIL}}', 'http://127.0.0.1:8000/kyc'), 'asha@example.com');
});
