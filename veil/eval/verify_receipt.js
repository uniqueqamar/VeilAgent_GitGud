// Standalone Cryptographic Receipt Chain Verifier for Veil Agent (Task 8)
// Checks SHA-256 hash chaining, prevHash linkage, and tamper-evidence.
// Can be run via CLI: node eval/verify_receipt.js <file.json>
// Or imported as a module: const { verifyReceiptChain } = require('./verify_receipt.js')

const crypto = require('crypto');
const fs = require('fs');

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Verifies a receipt chain.
 * @param {Array|Object} receiptExport - Array of receipts or exported receipt chain object
 * @returns {{ valid: boolean, count: number, head: string, error: string|null }}
 */
function verifyReceiptChain(receiptExport) {
  let receipts = [];
  if (Array.isArray(receiptExport)) {
    receipts = receiptExport;
  } else if (receiptExport && Array.isArray(receiptExport.receipts)) {
    receipts = receiptExport.receipts;
  } else {
    return { valid: false, count: 0, head: '', error: 'Invalid receipt export structure' };
  }

  if (receipts.length === 0) {
    return { valid: true, count: 0, head: '0'.repeat(64), error: null };
  }

  let expectedPrevHash = '0'.repeat(64);

  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];

    // 1. Verify prevHash link
    if (r.hashPrev !== expectedPrevHash) {
      return {
        valid: false,
        count: i,
        head: expectedPrevHash,
        error: `Broken hash chain at receipt ${i}: expected prevHash "${expectedPrevHash}", but found "${r.hashPrev}"`
      };
    }

    // 2. Reconstruct canonical receiptData object without 'hash'
    const receiptData = {
      time: r.time,
      counts: r.counts || {},
      mode: r.mode,
      bytes: r.bytes,
      redactionCount: r.redactionCount ?? 0,
      suspectTextCount: r.suspectTextCount ?? 0,
      hashPrev: r.hashPrev,
      vision: r.vision || null
    };

    const canonicalJson = JSON.stringify(receiptData);
    const computedHash = sha256Hex(canonicalJson);

    // 3. Verify hash integrity
    if (computedHash !== r.hash) {
      // Also try without new fields in case of legacy format
      const legacyData = {
        time: r.time,
        counts: r.counts || {},
        mode: r.mode,
        bytes: r.bytes,
        hashPrev: r.hashPrev,
        vision: r.vision || null
      };
      const legacyHash = sha256Hex(JSON.stringify(legacyData));
      if (legacyHash !== r.hash) {
        return {
          valid: false,
          count: i,
          head: expectedPrevHash,
          error: `Tampered receipt at index ${i}: hash mismatch (stored: "${r.hash}", computed: "${computedHash}")`
        };
      }
    }

    expectedPrevHash = r.hash;
  }

  return {
    valid: true,
    count: receipts.length,
    head: expectedPrevHash,
    error: null
  };
}

// CLI Execution support
if (require.main === module) {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: node verify_receipt.js <path-to-receipts.json>');
    process.exit(1);
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    const result = verifyReceiptChain(parsed);

    if (result.valid) {
      console.log(`✔ Receipt chain VERIFIED successfully.`);
      console.log(`  Count: ${result.count} receipts`);
      console.log(`  Chain Head: ${result.head}`);
      process.exit(0);
    } else {
      console.error(`✖ Receipt chain verification FAILED: ${result.error}`);
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error reading receipt file: ${err.message}`);
    process.exit(1);
  }
}

module.exports = {
  verifyReceiptChain,
  sha256Hex
};
