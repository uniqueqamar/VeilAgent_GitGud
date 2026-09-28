const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const EXTENSION_DIR = path.resolve(__dirname, '../extension');
const MANIFEST_PATH = path.resolve(EXTENSION_DIR, 'manifest.json');
const GATE_PATH = path.resolve(EXTENSION_DIR, 'privacy/gate.js');
const MODEL_LOADER_PATH = path.resolve(EXTENSION_DIR, 'privacy/model-loader.js');
const LIB_DIR = path.resolve(EXTENSION_DIR, 'lib');

function getAllJsFiles(dir) {
  let files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files = files.concat(getAllJsFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(fullPath);
    }
  }
  return files;
}

test('Repo Invariant 2: Only privacy/gate.js may make network calls', () => {
  const jsFiles = getAllJsFiles(EXTENSION_DIR);
  assert.ok(jsFiles.length > 0, 'Must find extension JavaScript files');

  const NETWORK_PATTERNS = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bWebSocket\b/,
    /\bsendBeacon\s*\(/
  ];

  const violations = [];

  for (const file of jsFiles) {
    const resolved = path.resolve(file);
    // Skip gate.js - exclusive designated egress gateway
    if (resolved === GATE_PATH) continue;
    // Skip model-loader.js - Invariant 12 single designated model loading exception
    if (resolved === MODEL_LOADER_PATH) continue;
    // Skip vendored third-party libraries (e.g. onnxruntime-web)
    if (resolved.startsWith(LIB_DIR)) continue;

    const content = fs.readFileSync(file, 'utf8');
    const relativePath = path.relative(EXTENSION_DIR, file);

    for (const pattern of NETWORK_PATTERNS) {
      if (pattern.test(content)) {
        violations.push({
          file: relativePath,
          pattern: pattern.toString()
        });
      }
    }
  }

  assert.deepStrictEqual(
    violations,
    [],
    `Invariant 2 VIOLATION: Network calls (fetch, XHR, WebSocket, sendBeacon) detected outside privacy/gate.js and privacy/model-loader.js:\n${JSON.stringify(violations, null, 2)}`
  );
});

test('Repo Invariant 12: privacy/model-loader.js is the only network exception and verifies pinned hashes', () => {
  assert.ok(fs.existsSync(MODEL_LOADER_PATH), 'privacy/model-loader.js must exist');
  const content = fs.readFileSync(MODEL_LOADER_PATH, 'utf8');

  // Verify SHA-256 verification logic exists
  assert.ok(content.includes('SHA-256'), 'model-loader.js must perform SHA-256 verification');
  assert.ok(content.includes('verifyModelBuffer') || content.includes('crypto.subtle.digest'), 'model-loader.js must compute cryptographic hash');
});

test('Manifest Permissions: host_permissions restricted strictly to server URL', () => {
  assert.ok(fs.existsSync(MANIFEST_PATH), 'manifest.json must exist');
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));

  assert.ok(Array.isArray(manifest.host_permissions), 'host_permissions must be an array');

  // Verify all host_permissions target only local server URL
  const ALLOWED_HOST_PREFIXES = [
    'http://localhost:8000/',
    'http://127.0.0.1:8000/'
  ];

  for (const perm of manifest.host_permissions) {
    const isAllowed = ALLOWED_HOST_PREFIXES.some((prefix) => perm.startsWith(prefix));
    assert.ok(
      isAllowed,
      `host_permission "${perm}" violates restriction. Only server URL allowed.`
    );
  }

  // Ensure no <all_urls> or broad web access in host_permissions
  assert.ok(!manifest.host_permissions.includes('<all_urls>'), 'host_permissions must not contain <all_urls>');
  assert.ok(!manifest.host_permissions.includes('*://*/*'), 'host_permissions must not contain wildcards');
});
