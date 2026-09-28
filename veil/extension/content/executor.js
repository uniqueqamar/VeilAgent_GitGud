// Executes one action by element ID. Real PII values are substituted by the
// background script from the local vault and never come from the server.
// Strictly enforces synthetic events only, anti-clickjacking, and stale-element recapture.
(() => {
  if (globalThis.__veil_executor_loaded) return;
  globalThis.__veil_executor_loaded = true;

  const api = globalThis.browser ?? globalThis.chrome;

  // Native prototype property setter (Task 7: never invoke page-defined function overrides)
  function setValue(el, value) {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) {
      desc.set.call(el, value);
    } else {
      el.value = value;
    }
    // Synthetic events only (Task 7)
    el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, data: value }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function waitForDomQuiet(quietMs = 250, maxTimeoutMs = 2500) {
    return new Promise((resolve) => {
      let timer = null;
      let maxTimer = null;
      let observer = null;

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        if (maxTimer) clearTimeout(maxTimer);
        if (observer) observer.disconnect();
      };

      const done = () => {
        cleanup();
        resolve();
      };

      try {
        observer = new MutationObserver(() => {
          if (timer) clearTimeout(timer);
          timer = setTimeout(done, quietMs);
        });

        if (document.documentElement || document.body) {
          observer.observe(document.documentElement || document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            characterData: true
          });
        }
      } catch (_) {}

      timer = setTimeout(done, quietMs);
      maxTimer = setTimeout(done, maxTimeoutMs);
    });
  }

  // Resolve target element supporting both local ("e5") and frame-qualified ("f2:e5") IDs
  function resolveTargetElement(targetId, idToEl) {
    if (!targetId || !idToEl) return null;
    if (idToEl.has(targetId)) return idToEl.get(targetId);

    // If frame-qualified like "f0:e5" or "f2:e5", strip prefix and check
    const m = targetId.match(/^f\d+:(.*)$/);
    if (m && idToEl.has(m[1])) {
      return idToEl.get(m[1]);
    }
    return null;
  }

  async function executeAction(action) {
    const WHITELIST = ['click', 'type', 'select', 'scroll', 'done'];
    if (!action || !WHITELIST.includes(action.action)) {
      return { ok: false, error: `unsupported action: ${action?.action}` };
    }

    if (action.action === 'done') {
      return { ok: true, done: true };
    }

    if (action.action === 'scroll') {
      window.scrollBy({ top: action.value === 'up' ? -600 : 600, behavior: 'instant' });
      await waitForDomQuiet(200, 2000);
      return { ok: true };
    }

    // Coordinate click for visual_only nodes (Invariant 16 & Task 4)
    if (action.action === 'click' && Array.isArray(action.coords) && action.coords.length === 2) {
      const [px, py] = action.coords;
      const targetEl = document.elementFromPoint(px, py);
      if (!targetEl) {
        return { ok: false, error: `no element found at coordinates (${px}, ${py})` };
      }
      // Synthetic events only (Task 7)
      const evOpts = { clientX: px, clientY: py, bubbles: true, cancelable: true, view: window };
      targetEl.dispatchEvent(new PointerEvent('pointerdown', evOpts));
      targetEl.dispatchEvent(new MouseEvent('mousedown', evOpts));
      targetEl.dispatchEvent(new PointerEvent('pointerup', evOpts));
      targetEl.dispatchEvent(new MouseEvent('mouseup', evOpts));
      targetEl.dispatchEvent(new MouseEvent('click', evOpts));
      await waitForDomQuiet(200, 2000);
      return { ok: true, coordinateClick: true, coords: [px, py] };
    }

    if (!action.target_id) {
      return { ok: false, error: `missing target_id for action ${action.action}` };
    }

    const { idToEl } = globalThis.__veil || {};
    if (!idToEl) {
      return { ok: false, error: 'DOM capture not initialized' };
    }

    const el = resolveTargetElement(action.target_id, idToEl);

    // Task 4: Dynamic page stale check - if detached, signal stale and NEVER guess!
    if (!el || !el.isConnected) {
      return {
        ok: false,
        stale: true,
        error: `target element ${action.target_id} is stale or detached from document (recapture required)`
      };
    }

    // Element visible and non-zero size
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    if (r.width <= 0 || r.height <= 0 || s.visibility === 'hidden' || s.display === 'none') {
      return { ok: false, error: `element ${action.target_id} is not visible or has zero size` };
    }

    // Anti-honeypot checks (Task 2 & 5)
    const isOffscreen = r.left < -100 || r.top < -100 || r.left > window.innerWidth + 5000;
    const isZeroOpacity = s.opacity === '0' || parseFloat(s.opacity) < 0.05;
    const isHiddenAria = el.getAttribute('aria-hidden') === 'true' && el.tabIndex === -1;
    const isIndented = parseInt(s.textIndent, 10) <= -100;
    const isPointerBlocked = s.pointerEvents === 'none';

    if (isOffscreen || isZeroOpacity || isHiddenAria || isIndented || isPointerBlocked) {
      return { ok: false, error: `element ${action.target_id} detected as honeypot` };
    }

    // Form same-origin post verification
    if (el.form && el.form.action) {
      try {
        const formActionUrl = new URL(el.form.action, window.location.href);
        if (
          window.location.origin &&
          window.location.origin !== 'null' &&
          formActionUrl.origin !== window.location.origin &&
          formActionUrl.protocol !== 'file:'
        ) {
          return { ok: false, error: 'target form posts cross-origin (refusing to fill identity fields)' };
        }
      } catch (_) {}
    }

    // Element enabled
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') {
      return { ok: false, error: `element ${action.target_id} is disabled` };
    }

    if (action.action === 'type') {
      const type = (el.getAttribute('type') || el.type || '').toLowerCase();
      const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
      const name = (el.getAttribute('name') || '').toLowerCase();
      const id = (el.id || '').toLowerCase();

      // Enforce in extension: never type into password/OTP/card/hidden/file inputs
      if (type === 'password' || type === 'hidden' || type === 'file') {
        return { ok: false, error: `forbidden to type into input of type '${type}'` };
      }

      const sensitivePattern = /otp|one-time-code|2fa|mfa|token|cvv|cvc|card|credit|debit/;
      if (sensitivePattern.test(type) || sensitivePattern.test(ac) || sensitivePattern.test(name) || sensitivePattern.test(id)) {
        return { ok: false, error: `forbidden to type into sensitive field (${name || id || type})` };
      }

      if (typeof action.value !== 'string') {
        return { ok: false, error: 'typed value must be a string' };
      }

      if (action.value.length > 100) {
        return { ok: false, error: 'typed value exceeds 100 characters' };
      }

      el.focus();
      setValue(el, action.value);
      await waitForDomQuiet(200, 2000);
      return { ok: true };
    }

    if (action.action === 'click') {
      // Task 7: Target stability across scroll
      const preScrollEl = el;
      el.scrollIntoView({ block: 'center', behavior: 'instant' });

      // Verify target is unchanged and still connected after scroll (Task 7)
      if (!preScrollEl.isConnected || preScrollEl !== el) {
        return {
          ok: false,
          stale: true,
          error: `target element ${action.target_id} changed or detached during scroll`
        };
      }

      // Task 6: Clickjacking and honeypots immediately before click re-check
      const curBox = el.getBoundingClientRect();
      const cx = Math.round(curBox.left + curBox.width / 2);
      const cy = Math.round(curBox.top + curBox.height / 2);

      const topEl = document.elementFromPoint(cx, cy);
      if (!topEl || (topEl !== el && !el.contains(topEl))) {
        return {
          ok: false,
          error: `clickjacking overlay detected: elementFromPoint at center (${cx}, ${cy}) did not match target element`
        };
      }

      // Task 7: Synthetic events only (never call el.click() to avoid malicious page overrides)
      const evOpts = { clientX: cx, clientY: cy, bubbles: true, cancelable: true, view: window };
      el.dispatchEvent(new PointerEvent('pointerdown', evOpts));
      el.dispatchEvent(new MouseEvent('mousedown', evOpts));
      el.focus();
      el.dispatchEvent(new PointerEvent('pointerup', evOpts));
      el.dispatchEvent(new MouseEvent('mouseup', evOpts));
      el.dispatchEvent(new MouseEvent('click', evOpts));

      await waitForDomQuiet(200, 2000);
      return { ok: true };
    }

    if (action.action === 'select') {
      el.value = action.value;
      el.dispatchEvent(new Event('change', { bubbles: true }));
      await waitForDomQuiet(200, 2000);
      return { ok: true };
    }

    return { ok: false, error: `unsupported action: ${action.action}` };
  }

  // Content script execution listener (Never accepts window.postMessage from page)
  api.runtime.onMessage.addListener((msg, sender, reply) => {
    if (msg?.type === 'PING') {
      reply({ ok: true });
      return false;
    }
    if (msg?.type === 'WAIT_QUIET') {
      waitForDomQuiet(250, 2500).then(() => reply({ ok: true }));
      return true;
    }
    if (msg?.type === 'EXECUTE') {
      executeAction(msg.action)
        .then(reply)
        .catch((e) => reply({ ok: false, error: e.message }));
      return true;
    }
  });
})();
