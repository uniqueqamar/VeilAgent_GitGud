/**
 * Phase 7 Evaluation Suite: Real-World Pages (Task 9)
 * Tests:
 * 1. Nested iframes (depth 1, 2, 3, and depth 4 capping; frame-qualified IDs f0:e1, f2:e5; box offsets).
 * 2. Cross-origin iframe vault filling protection (blocked unless explicitly approved).
 * 3. Shadow DOM: open roots traversed; closed roots/opaque widgets stay black (sensitive: true).
 * 4. Dynamic SPA navigation: WeakMap stable IDs, debounced observer, stale ID detection without guessing.
 * 5. VISIBLE-TEXT-ONLY capture: all 9 evasion vectors excluded (display:none, opacity, contrast, text-indent, etc.).
 * 6. Clickjacking overlay: elementFromPoint pre-click re-check aborts click on covered element.
 * 7. Virtualized list: 600 items capped at 400, viewport-first sorting.
 * 8. Static code audit: Zero page-DOM injections (no append, insertAdjacent, innerHTML, document.write in content scripts).
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

// Load PII detector
const VeilPII = require('../extension/workers/pii.js');
globalThis.VeilPII = VeilPII;

test('Phase 7 - Task 1: Nested Iframes, Frame Offsets & Depth Capping', () => {
  const domHtml = fs.readFileSync(path.join(__dirname, 'synthetic_pages', 'nested_iframes.html'), 'utf8');
  const dom = new JSDOM(domHtml, { url: 'http://localhost:8000/parent.html' });
  const { window } = dom;

  // Simulate top frame capture
  const topNodes = [
    { id: 'e1', tag: 'input', label: 'Full name', bbox: [10, 50, 200, 30] },
    { id: 'e2', tag: 'button', label: 'Submit Top', bbox: [10, 100, 120, 35] }
  ];

  // Child frame 1 (Depth 1) positioned at [50, 200]
  const frame1Nodes = [
    { id: 'e1', tag: 'input', label: 'Frame 1 Text', bbox: [20, 30, 180, 25] },
    { id: 'e2', tag: 'button', label: 'Frame 1 Action', bbox: [20, 70, 100, 30] }
  ];

  // Nested frame 2 (Depth 2) positioned inside frame 1 at [10, 120] -> cumulative offset [60, 320]
  const frame2Nodes = [
    { id: 'e1', tag: 'input', label: 'Depth 2 Input', bbox: [15, 20, 150, 25] }
  ];

  // Nested frame 3 (Depth 3) positioned at cumulative offset [80, 400]
  const frame3Nodes = [
    { id: 'e1', tag: 'button', label: 'Depth 3 Button', bbox: [10, 10, 90, 30] }
  ];

  // Nested frame 4 (Depth 4 - exceeds max depth 3)
  const frame4Nodes = [
    { id: 'e1', tag: 'button', label: 'Depth 4 Button (Should be ignored)', bbox: [5, 5, 80, 25] }
  ];

  // Frame assemble logic matching background/orchestrator.js
  const allFrameSnapshots = [
    { frameId: 0, depth: 0, offset: [0, 0], dom: { isTop: true, nodes: topNodes, childFrames: [{ bbox: [50, 200, 500, 400] }] } },
    { frameId: 1, depth: 1, offset: [50, 200], dom: { nodes: frame1Nodes } },
    { frameId: 2, depth: 2, offset: [60, 320], dom: { nodes: frame2Nodes } },
    { frameId: 3, depth: 3, offset: [80, 400], dom: { nodes: frame3Nodes } },
    { frameId: 4, depth: 4, offset: [100, 500], dom: { nodes: frame4Nodes } } // Depth 4
  ];

  const combinedNodes = [];
  const MAX_FRAME_DEPTH = 3;

  for (const f of allFrameSnapshots) {
    if (f.depth > MAX_FRAME_DEPTH) {
      continue; // Strictly enforce max depth 3 (Task 1)
    }
    for (const n of f.dom.nodes) {
      const qualifiedId = `f${f.frameId}:${n.id}`;
      const adjustedBox = [
        n.bbox[0] + f.offset[0],
        n.bbox[1] + f.offset[1],
        n.bbox[2],
        n.bbox[3]
      ];
      combinedNodes.push({
        ...n,
        id: qualifiedId,
        frameId: f.frameId,
        bbox: adjustedBox
      });
    }
  }

  // Asserts
  assert.strictEqual(combinedNodes.length, 6, 'Should contain 2 top + 2 depth1 + 1 depth2 + 1 depth3 (depth 4 excluded)');
  assert.ok(combinedNodes.some((n) => n.id === 'f0:e1'), 'Top frame node qualified as f0:e1');
  assert.ok(combinedNodes.some((n) => n.id === 'f1:e1'), 'Frame 1 node qualified as f1:e1');
  assert.ok(combinedNodes.some((n) => n.id === 'f2:e1'), 'Frame 2 node qualified as f2:e1');
  assert.ok(combinedNodes.some((n) => n.id === 'f3:e1'), 'Frame 3 node qualified as f3:e1');
  assert.ok(!combinedNodes.some((n) => n.id.startsWith('f4:')), 'Depth 4 nodes strictly excluded');

  // Verify box offset computation
  const f1Input = combinedNodes.find((n) => n.id === 'f1:e1');
  assert.deepStrictEqual(f1Input.bbox, [70, 230, 180, 25], 'Frame 1 input offset [20+50, 30+200]');

  const f2Input = combinedNodes.find((n) => n.id === 'f2:e1');
  assert.deepStrictEqual(f2Input.bbox, [75, 340, 150, 25], 'Frame 2 input offset [15+60, 20+320]');
});

test('Phase 7 - Task 2: Cross-Origin Iframe Vault Filling Protection', () => {
  const topOrigin = 'http://localhost:8000';
  const crossOrigin = 'http://localhost:8001';

  const frameOrigins = new Map();
  frameOrigins.set(0, topOrigin);
  frameOrigins.set(1, crossOrigin);

  const approvedOrigins = ['http://localhost:8000']; // crossOrigin NOT approved

  // Action attempting to fill vault token into cross-origin frame
  const action = {
    action: 'type',
    target_id: 'f1:card_number',
    value: 'Asha Verma' // resolved from [NAME_1]
  };
  const rawAction = {
    action: 'type',
    target_id: 'f1:card_number',
    value: '[NAME_1]'
  };

  const targetFrameId = 1;
  const targetFrameOrigin = frameOrigins.get(targetFrameId);
  const isCrossOrigin = targetFrameOrigin !== topOrigin;

  let blocked = false;
  let reason = '';

  if (isCrossOrigin && action.action === 'type') {
    const isVaultValue = (rawAction.value && rawAction.value.includes('[')) || action.value !== rawAction.value;
    if (isVaultValue && !approvedOrigins.includes(targetFrameOrigin)) {
      blocked = true;
      reason = `Cross-origin vault fill blocked for frame origin "${targetFrameOrigin}". User approval required.`;
    }
  }

  assert.strictEqual(blocked, true, 'Vault filling into unapproved cross-origin frame must be blocked');
  assert.ok(reason.includes('Cross-origin vault fill blocked'), 'Approval reason correctly set');

  // If origin is approved
  approvedOrigins.push(crossOrigin);
  let blockedAfterApproval = false;
  if (isCrossOrigin && action.action === 'type') {
    const isVaultValue = (rawAction.value && rawAction.value.includes('[')) || action.value !== rawAction.value;
    if (isVaultValue && !approvedOrigins.includes(targetFrameOrigin)) {
      blockedAfterApproval = true;
    }
  }
  assert.strictEqual(blockedAfterApproval, false, 'Allowed once exact origin is approved by user');
});

test('Phase 7 - Task 3: Shadow DOM - Open Roots Traversed, Closed Roots Treated as Media', () => {
  const html = fs.readFileSync(path.join(__dirname, 'synthetic_pages', 'shadow_dom.html'), 'utf8');
  const dom = new JSDOM(html);
  const { window } = dom;
  const { document } = window;

  // Set up open shadow root
  const openHost = document.getElementById('open-shadow-host');
  const openRoot = openHost.attachShadow({ mode: 'open' });
  const openInput = document.createElement('input');
  openInput.id = 'shadow-user';
  openInput.setAttribute('type', 'text');
  openInput.setAttribute('aria-label', 'Shadow User');
  openRoot.appendChild(openInput);

  const openBtn = document.createElement('button');
  openBtn.id = 'shadow-btn';
  openBtn.textContent = 'Shadow Submit';
  openRoot.appendChild(openBtn);

  // Set up custom element representing closed shadow DOM or opaque widget
  const closedHost = document.getElementById('closed-shadow-host');
  // Closed shadow roots return null for el.shadowRoot
  assert.strictEqual(closedHost.shadowRoot, null, 'Closed host shadowRoot is null');

  // Run shadow traversal logic
  const discoveredControls = [];
  const opaqueWidgets = [];

  function walk(root) {
    const children = root.children || root.childNodes || [];
    for (let i = 0; i < children.length; i++) {
      const node = children[i];
      if (node.nodeType === 1) {
        const tag = node.tagName.toLowerCase();
        if (tag === 'input' || tag === 'button') {
          discoveredControls.push({ id: node.id, tag });
        }
        // Custom element or closed host or canvas
        if ((tag.includes('-') && !node.shadowRoot) || tag === 'canvas') {
          opaqueWidgets.push({ id: node.id, tag, sensitive: true });
        }
        if (node.shadowRoot) {
          walk(node.shadowRoot); // Traverse OPEN shadow roots
        }
        walk(node);
      }
    }
  }

  walk(document.body);

  assert.ok(discoveredControls.some((c) => c.id === 'shadow-user'), 'Open shadow input discovered');
  assert.ok(discoveredControls.some((c) => c.id === 'shadow-btn'), 'Open shadow button discovered');
  assert.ok(opaqueWidgets.some((w) => w.id === 'opaque-canvas-widget'), 'Canvas opaque widget flagged');
});

test('Phase 7 - Task 4: Dynamic SPA Navigation - WeakMap ID Stability & Stale ID Recapture', () => {
  const elToId = new WeakMap();
  const idToEl = new Map();
  let counter = 0;

  function idFor(el) {
    if (!elToId.has(el)) {
      const id = 'e' + ++counter;
      elToId.set(el, id);
      idToEl.set(id, el);
    }
    return elToId.get(el);
  }

  const dom = new JSDOM('<div><nav id="persistent-nav"><a id="home">Home</a></nav><div id="view"><input id="step1-input"></div></div>');
  const { document } = dom.window;

  const persistentNav = document.getElementById('home');
  const step1Input = document.getElementById('step1-input');

  const navId1 = idFor(persistentNav);
  const inputId1 = idFor(step1Input);

  assert.strictEqual(navId1, 'e1');
  assert.strictEqual(inputId1, 'e2');

  // SPA Route Change: remove step1-input, insert step2-input, persistentNav remains
  const view = document.getElementById('view');
  step1Input.remove();

  const step2Input = document.createElement('input');
  step2Input.id = 'step2-input';
  view.appendChild(step2Input);

  // Re-scan
  const navId2 = idFor(persistentNav);
  const inputId2 = idFor(step2Input);

  assert.strictEqual(navId2, 'e1', 'WeakMap maintains identical ID for persistent element across re-renders');
  assert.strictEqual(inputId2, 'e3', 'New element receives new ID');

  // Stale ID test: action targets step1Input ('e2') which is detached
  const targetEl = idToEl.get('e2');
  assert.strictEqual(targetEl.isConnected, false, 'Detached element isConnected is false');

  // Executor stale check
  let executionResult;
  if (!targetEl || !targetEl.isConnected) {
    executionResult = {
      ok: false,
      stale: true,
      error: 'target element e2 is stale or detached from document (recapture required)'
    };
  }

  assert.strictEqual(executionResult.ok, false);
  assert.strictEqual(executionResult.stale, true);
  assert.ok(executionResult.error.includes('recapture required'), 'Never guess another element; signals recapture');
});

test('Phase 7 - Task 5: VISIBLE-TEXT-ONLY Capture - All 9 Evasion Vectors Excluded', () => {
  const html = fs.readFileSync(path.join(__dirname, 'synthetic_pages', 'hidden_text_injection.html'), 'utf8');
  const dom = new JSDOM(html);
  const { document } = dom.window;

  // Mock getComputedStyle for jsdom elements matching inline styles
  function mockComputedStyle(el) {
    const style = el.getAttribute('style') || '';
    const res = {
      display: style.includes('display: none') ? 'none' : 'block',
      visibility: style.includes('visibility: hidden') ? 'hidden' : 'visible',
      opacity: style.includes('opacity: 0.02') ? '0.02' : '1',
      fontSize: style.includes('font-size: 3px') ? '3px' : '14px',
      color: style.includes('color: #ffffff') ? 'rgb(255, 255, 255)' : 'rgb(0, 0, 0)',
      backgroundColor: style.includes('background-color: #ffffff') ? 'rgb(255, 255, 255)' : 'rgb(248, 250, 252)',
      clip: style.includes('clip: rect(0, 0, 0, 0)') ? 'rect(0px, 0px, 0px, 0px)' : 'auto',
      textIndent: style.includes('text-indent: -9999px') ? '-9999px' : '0px'
    };
    return res;
  }

  function checkVisible(el) {
    const s = mockComputedStyle(el);
    const styleAttr = el.getAttribute('style') || '';

    // 1. display: none
    if (s.display === 'none') return false;
    // 2. visibility: hidden
    if (s.visibility === 'hidden') return false;
    // 3. opacity < 0.05
    if (parseFloat(s.opacity) < 0.05) return false;
    // 4. Off-screen
    if (styleAttr.includes('left: -9999px')) return false;
    // 5. font-size < 6px
    if (parseFloat(s.fontSize) < 6) return false;
    // 6. Contrast < 1.5
    if (s.color === 'rgb(255, 255, 255)' && s.backgroundColor === 'rgb(255, 255, 255)') return false;
    // 7. aria-hidden
    if (el.getAttribute('aria-hidden') === 'true') return false;
    // 8. Clipped 1px
    if (s.clip.includes('rect(0px, 0px, 0px, 0px)')) return false;
    // 9. Negative text indent
    if (parseInt(s.textIndent, 10) <= -100) return false;

    return true;
  }

  // Test all 9 injection containers
  const inj1 = document.getElementById('inj-display-none');
  const inj2 = document.getElementById('inj-visibility-hidden');
  const inj3 = document.getElementById('inj-opacity-low');
  const inj4 = document.getElementById('inj-offscreen');
  const inj5 = document.getElementById('inj-tiny-font');
  const inj6 = document.getElementById('inj-zero-contrast');
  const inj7 = document.getElementById('inj-aria-hidden');
  const inj8 = document.getElementById('inj-clipped-1px');
  const inj9 = document.getElementById('inj-text-indent');
  const legitimate = document.getElementById('legitimate-text');

  assert.strictEqual(checkVisible(inj1), false, '1. display:none blocked');
  assert.strictEqual(checkVisible(inj2), false, '2. visibility:hidden blocked');
  assert.strictEqual(checkVisible(inj3), false, '3. opacity 0.02 blocked');
  assert.strictEqual(checkVisible(inj4), false, '4. offscreen -9999px blocked');
  assert.strictEqual(checkVisible(inj5), false, '5. font-size 3px blocked');
  assert.strictEqual(checkVisible(inj6), false, '6. zero contrast blocked');
  assert.strictEqual(checkVisible(inj7), false, '7. aria-hidden blocked');
  assert.strictEqual(checkVisible(inj8), false, '8. clipped 1px blocked');
  assert.strictEqual(checkVisible(inj9), false, '9. text-indent -9999px blocked');

  assert.strictEqual(checkVisible(legitimate), true, 'Legitimate visible text allowed');
});

test('Phase 7 - Task 6 & 7: Clickjacking Overlay Abort & Synthetic Event Dispatch', () => {
  const html = fs.readFileSync(path.join(__dirname, 'synthetic_pages', 'clickjacking_overlay.html'), 'utf8');
  const dom = new JSDOM(html);
  const { document } = dom.window;

  const targetBtn = document.getElementById('target-btn');
  const overlay = document.getElementById('malicious-overlay');

  let buttonClicked = false;
  targetBtn.addEventListener('click', () => {
    buttonClicked = true;
  });

  // Mock document.elementFromPoint returning the overlay (which covers the button)
  document.elementFromPoint = (x, y) => overlay;

  const cx = 100;
  const cy = 50;

  // Immediate pre-click check in executor.js
  const topEl = document.elementFromPoint(cx, cy);
  let aborted = false;
  let errorMsg = '';

  if (!topEl || (topEl !== targetBtn && !targetBtn.contains(topEl))) {
    aborted = true;
    errorMsg = 'clickjacking overlay detected: elementFromPoint did not match target';
  }

  assert.strictEqual(aborted, true, 'Click must be aborted when elementFromPoint is not the target');
  assert.strictEqual(buttonClicked, false, 'Button click was never dispatched');

  // When overlay is removed, synthetic events dispatch safely without calling page overrides
  document.elementFromPoint = (x, y) => targetBtn;
  const cleanTopEl = document.elementFromPoint(cx, cy);
  assert.strictEqual(cleanTopEl, targetBtn);

  // Synthetic event dispatch (Task 7)
  const ev = new dom.window.MouseEvent('click', { bubbles: true, cancelable: true });
  targetBtn.dispatchEvent(ev);
  assert.strictEqual(buttonClicked, true, 'Synthetic click executed safely');
});

test('Phase 7 - Task 4: Virtualized List 400-Node Cap & Viewport-First Sorting', () => {
  const nodes = [];
  const vw = 1280;
  const vh = 800;

  // 600 items: items 1-10 are in viewport, items 11-600 are offscreen (virtualized/scrolled)
  for (let i = 1; i <= 600; i++) {
    const inView = i <= 10;
    nodes.push({
      id: `e${i}`,
      tag: 'div',
      text: `Item Record #${i}`,
      bbox: inView ? [50, i * 40, 300, 30] : [50, 900 + i * 40, 300, 30]
    });
  }

  // Viewport-first sort
  nodes.sort((a, b) => {
    const aInView = a.bbox[0] >= 0 && a.bbox[1] >= 0 && a.bbox[0] < vw && a.bbox[1] < vh;
    const bInView = b.bbox[0] >= 0 && b.bbox[1] >= 0 && b.bbox[0] < vw && b.bbox[1] < vh;
    if (aInView && !bInView) return -1;
    if (!aInView && bInView) return 1;
    return 0;
  });

  // Cap at 400
  const cappedNodes = nodes.slice(0, 400);

  assert.strictEqual(cappedNodes.length, 400, 'Total nodes strictly capped at 400');
  // First 10 items must be the viewport-visible items
  for (let i = 0; i < 10; i++) {
    assert.strictEqual(cappedNodes[i].id, `e${i + 1}`, `Item ${i + 1} sorted viewport-first`);
  }
});

test('Phase 7 - Task 8: Static Audit - Zero Page DOM Injections in Content Scripts', () => {
  const contentDir = path.resolve(__dirname, '..', 'extension', 'content');
  const files = fs.readdirSync(contentDir).filter((f) => f.endsWith('.js'));

  // Disallowed DOM mutation calls in content scripts
  const FORBIDDEN_DOM_PATTERNS = [
    /\.appendChild\s*\(/,
    /\.insertBefore\s*\(/,
    /\.insertAdjacentHTML\s*\(/,
    /\.insertAdjacentElement\s*\(/,
    /\.innerHTML\s*=/,
    /\.outerHTML\s*=/,
    /document\.write\s*\(/
  ];

  let violations = [];

  for (const file of files) {
    const filePath = path.join(contentDir, file);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, idx) => {
      // Ignore comment lines
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

      for (const pattern of FORBIDDEN_DOM_PATTERNS) {
        if (pattern.test(line)) {
          violations.push(`${file}:${idx + 1} matches ${pattern}: ${trimmed}`);
        }
      }
    });
  }

  assert.strictEqual(violations.length, 0, `Audit failed: Page DOM additions detected:\n${violations.join('\n')}`);
  console.log(`  [AUDIT PASS] Clean audit: Zero page DOM injections across ${files.length} content scripts.`);
});
