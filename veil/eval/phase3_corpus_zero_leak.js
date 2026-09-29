/**
 * Phase 3 Corpus Zero-Leakage Evaluation Script (Task 7)
 * Runs over both Dev (60 pages) and Held-Out (40 pages) corpus.
 * Verifies that NO ground-truth expected PII value appears in any outgoing sanitized DOM payload.
 * Also verifies that all sanitized payloads pass Gate assertions cleanly.
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

// Load Dual-Runtime VeilPII and VeilGate
const VeilPII = require('../extension/workers/pii.js');
globalThis.VeilPII = VeilPII;
const VeilGate = require('../extension/privacy/gate.js');

const CORPUS_DIR = path.resolve(__dirname, 'corpus');
const DEV_DIR = path.join(CORPUS_DIR, 'dev');
const HELD_OUT_DIR = path.join(CORPUS_DIR, 'held_out');

// Clean and normalize strings for PII leak comparison
function normalizePii(val) {
  if (!val) return '';
  return val.toString().trim().toLowerCase().replace(/[\s-]/g, '');
}

// In-place scan and redaction (mirrors dom-capture.js)
function scanAndRedact(str) {
  if (!str || typeof str !== 'string') return { text: str || '', piiTypes: [] };
  const findings = VeilPII.detectPII(str);
  if (!findings || findings.length === 0) return { text: str, piiTypes: [] };

  const piiTypes = [...new Set(findings.map((f) => f.type))];
  const sorted = [...findings].sort((a, b) => b.start - a.start);
  let redacted = str;
  for (const f of sorted) {
    const tag = `[REDACTED:${f.type.toUpperCase()}]`;
    redacted = redacted.slice(0, f.start) + tag + redacted.slice(f.end);
  }
  return { text: redacted, piiTypes };
}

function captureDomFromDocument(doc) {
  const nodes = [];
  let counter = 0;

  // Form controls
  doc.querySelectorAll('button, input, select, textarea, [role=button]').forEach((el) => {
    counter++;
    const type = (el.getAttribute('type') || '').toLowerCase();
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    const name = (el.getAttribute('name') || '').toLowerCase();
    const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();

    let rawLabel = el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('title') || '';
    if (!rawLabel && el.labels && el.labels[0]) {
      rawLabel = el.labels[0].textContent || '';
    } else if (!rawLabel) {
      rawLabel = el.textContent || '';
    }

    const redactedLabel = scanAndRedact(rawLabel);
    const classification = VeilPII.classifyField({ type, autocomplete: ac, name, id: el.id, label: rawLabel, placeholder });

    const allPii = [...new Set([...redactedLabel.piiTypes, ...(classification.pii_type ? [classification.pii_type] : [])])];

    nodes.push({
      id: 'e' + counter,
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute('role') || null,
      type: type || null,
      label: redactedLabel.text.slice(0, 40),
      text: redactedLabel.text.slice(0, 200),
      autocomplete: ac || null,
      sensitive: classification.sensitive || type === 'password' || allPii.length > 0,
      pii: allPii,
      bbox: [10, 10, 100, 30]
    });
  });

  // Text blocks
  doc.querySelectorAll('h1, h2, h3, h4, h5, h6, p, li, td, th, [role=text]').forEach((el) => {
    counter++;
    const rawText = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 200);
    if (!rawText) return;
    const redacted = scanAndRedact(rawText);

    nodes.push({
      id: 'e' + counter,
      tag: el.tagName.toLowerCase(),
      role: 'text',
      type: null,
      label: '',
      text: redacted.text,
      autocomplete: null,
      sensitive: redacted.piiTypes.length > 0,
      pii: redacted.piiTypes,
      bbox: [10, 10, 100, 30]
    });
  });

  // Title
  const titleScan = scanAndRedact(doc.title || '');

  return {
    url: 'http://127.0.0.1:8000',
    title: titleScan.text,
    viewport: [1280, 720],
    scrollY: 0,
    nodes
  };
}

function evaluateDirectory(dirPath, setName) {
  const expectedPath = path.join(dirPath, 'expected.json');
  if (!fs.existsSync(expectedPath)) {
    throw new Error(`expected.json missing in ${dirPath}`);
  }

  const expectedList = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));
  const positiveTargets = expectedList.filter((e) => e.category === 'positive');

  // Group by page
  const pageToTargets = new Map();
  for (const t of positiveTargets) {
    if (!pageToTargets.has(t.page)) {
      pageToTargets.set(t.page, []);
    }
    pageToTargets.get(t.page).push(t);
  }

  const htmlFiles = fs.readdirSync(dirPath).filter((f) => f.endsWith('.html'));

  let totalPages = 0;
  let totalTargetsChecked = 0;
  let leakViolations = [];
  let gateRejections = 0;

  for (const file of htmlFiles) {
    totalPages++;
    const filePath = path.join(dirPath, file);
    const html = fs.readFileSync(filePath, 'utf8');
    const dom = new JSDOM(html);
    const doc = dom.window.document;

    const sanitizedDom = captureDomFromDocument(doc);
    const expectedForPage = pageToTargets.get(file) || [];

    // Construct full payload as gate receives it
    const payload = {
      goal: 'verify user profile without leaks',
      step: 1,
      dom: sanitizedDom,
      screenshot: null,
      redactions: [],
      history: [],
      mode: 'Strict'
    };

    // 1. Verify gate.assertClean
    try {
      VeilGate.assertClean(payload);
    } catch (gateErr) {
      gateRejections++;
      leakViolations.push({
        set: setName,
        page: file,
        reason: `Gate rejected payload: ${gateErr.message}`
      });
    }

    // 2. Check every outgoing text string against ground-truth positive PII
    const outgoingStrings = [
      sanitizedDom.title,
      sanitizedDom.url,
      ...sanitizedDom.nodes.map((n) => n.label || ''),
      ...sanitizedDom.nodes.map((n) => n.text || '')
    ].filter(Boolean);

    for (const target of expectedForPage) {
      totalTargetsChecked++;
      const normTarget = normalizePii(target.value);
      if (!normTarget || normTarget.length < 3) continue;

      for (const str of outgoingStrings) {
        const normStr = normalizePii(str);
        if (normStr.includes(normTarget)) {
          leakViolations.push({
            set: setName,
            page: file,
            type: target.type,
            leakedValue: target.value,
            snippet: str.slice(0, 100)
          });
          break;
        }
      }
    }
  }

  return {
    setName,
    totalPages,
    totalTargetsChecked,
    leakCount: leakViolations.length,
    gateRejections,
    leakViolations
  };
}

function runEvaluation() {
  console.log('================================================================================');
  console.log('PHASE 3 ZERO-LEAKAGE CORPUS AUDIT');
  console.log('================================================================================\n');

  const devResults = evaluateDirectory(DEV_DIR, 'Dev Set (60 pages)');
  const heldOutResults = evaluateDirectory(HELD_OUT_DIR, 'Held-Out Set (40 pages)');

  const totalPages = devResults.totalPages + heldOutResults.totalPages;
  const totalTargets = devResults.totalTargetsChecked + heldOutResults.totalTargetsChecked;
  const totalLeaks = devResults.leakCount + heldOutResults.leakCount;

  console.log(`[Dev Set] Scanned ${devResults.totalPages} pages, verified ${devResults.totalTargetsChecked} ground-truth PII targets.`);
  console.log(`[Dev Set] Leaks Detected: ${devResults.leakCount} | Gate Rejections: ${devResults.gateRejections}`);

  console.log(`\n[Held-Out Set] Scanned ${heldOutResults.totalPages} pages, verified ${heldOutResults.totalTargetsChecked} ground-truth PII targets.`);
  console.log(`[Held-Out Set] Leaks Detected: ${heldOutResults.leakCount} | Gate Rejections: ${heldOutResults.gateRejections}`);

  console.log('\n--------------------------------------------------------------------------------');
  console.log(`TOTAL AUDITED: ${totalPages} pages | ${totalTargets} PII targets | ZERO-LEAKAGE STATUS: ${totalLeaks === 0 ? 'PASSED (0 LEAKS)' : 'FAILED'}`);
  console.log('--------------------------------------------------------------------------------\n');

  if (totalLeaks > 0) {
    console.error('LEAK VIOLATIONS OBSERVED:');
    for (const v of [...devResults.leakViolations, ...heldOutResults.leakViolations].slice(0, 10)) {
      console.error(JSON.stringify(v, null, 2));
    }
    process.exit(1);
  } else {
    console.log('ALL 100 SYNTHETIC CORPUS PAGES CONFIRMED ZERO PII LEAKAGE IN OUTGOING PAYLOADS!');
  }
}

runEvaluation();
