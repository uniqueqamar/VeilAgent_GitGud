/**
 * Runner for VeilPII Detector over Synthetic Corpus (Task 6).
 * Uses jsdom to parse DOM structure and attributes, calls VeilPII.detectPII,
 * and writes findings.json for dev and held-out sets.
 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');
const pii = require('../extension/workers/pii.js');

const BASE_DIR = path.resolve(__dirname);
const DEV_DIR = path.join(BASE_DIR, 'corpus', 'dev');
const HELD_OUT_DIR = path.join(BASE_DIR, 'corpus', 'held_out');

function scanDirectory(dirPath) {
  const files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.html'));
  const findings = [];

  for (const file of files) {
    const filePath = path.join(dirPath, file);
    const htmlContent = fs.readFileSync(filePath, 'utf-8');
    const dom = new JSDOM(htmlContent);
    const doc = dom.window.document;

    const seenValues = new Set();

    function recordFinding(type, val, loc, conf) {
      const cleanVal = (val || '').trim();
      if (!cleanVal) return;
      const key = `${type}::${cleanVal}`;
      if (!seenValues.has(key)) {
        seenValues.add(key);
        findings.push({
          page: file,
          type,
          value: cleanVal,
          confidence: conf,
          location: loc
        });
      }
    }

    // 1. Scan title
    if (doc.title) {
      const titleMatches = pii.detectPII(doc.title);
      for (const m of titleMatches) {
        recordFinding(m.type, m.value, 'title', m.confidence);
      }
    }

    // 2. Scan attributes (placeholder, aria-label, alt, title)
    const allEls = doc.querySelectorAll('*');
    for (const el of allEls) {
      const tag = el.tagName.toLowerCase();
      const attrs = ['placeholder', 'aria-label', 'alt', 'title', 'name'];
      for (const attr of attrs) {
        const val = el.getAttribute(attr);
        if (val) {
          const matches = pii.detectPII(val);
          for (const m of matches) {
            recordFinding(m.type, m.value, `${tag}[${attr}]`, m.confidence);
          }
        }
      }
    }

    // 3. Scan text elements (paragraphs, spans, headings, list items, code, table cells)
    const textEls = doc.querySelectorAll('p, span, h1, h2, h3, h4, h5, h6, li, td, th, pre, code');
    for (const el of textEls) {
      // Direct text or innerText
      const text = el.textContent || '';
      if (text.trim().length > 0) {
        const matches = pii.detectPII(text);
        for (const m of matches) {
          recordFinding(m.type, m.value, el.tagName.toLowerCase(), m.confidence);
        }
      }
    }
  }

  const outPath = path.join(dirPath, 'findings.json');
  fs.writeFileSync(outPath, JSON.stringify(findings, null, 2), 'utf-8');
  console.log(`Scanned ${files.length} pages in ${path.basename(dirPath)}: recorded ${findings.length} findings to ${outPath}`);
  return findings;
}

function run() {
  console.log('--- Running VeilPII Detection on Synthetic Corpus ---');
  if (fs.existsSync(DEV_DIR)) {
    scanDirectory(DEV_DIR);
  }
  if (fs.existsSync(HELD_OUT_DIR)) {
    scanDirectory(HELD_OUT_DIR);
  }
  console.log('Detection complete.');
}

run();
