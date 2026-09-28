// Executes one action by element ID. Real PII values are substituted by the
// background script from the local vault and never come from the server.
(() => {
  if (globalThis.__veil_executor_loaded) return;
  globalThis.__veil_executor_loaded = true;

  const api = globalThis.browser ?? globalThis.chrome;

  function setValue(el, value) {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) {
      desc.set.call(el, value); // works with React and frameworks
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function waitForDomQuiet(quietMs = 300, maxTimeoutMs = 3000) {
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

        observer.observe(document.documentElement || document.body, {
          childList: true,
          subtree: true,
          attributes: true,
          characterData: true
        });
      } catch (_) {
        // Fallback if MutationObserver fails
      }

      timer = setTimeout(done, quietMs);
      maxTimer = setTimeout(done, maxTimeoutMs);
    });
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
      window.scrollBy({ top: action.value === 'up' ? -600 : 600, behavior: 'smooth' });
      await waitForDomQuiet(300, 3000);
      return { ok: true };
    }

    // click, type, select require target_id
    const { idToEl } = globalThis.__veil || {};
    if (!idToEl) {
      return { ok: false, error: 'DOM capture not initialized' };
    }

    // Coordinate click for visual_only nodes (Invariant 16 & Task 4)
    if (action.action === 'click' && Array.isArray(action.coords) && action.coords.length === 2) {
      const [px, py] = action.coords;
      const targetEl = document.elementFromPoint(px, py);
      if (!targetEl) {
        return { ok: false, error: `no element found at coordinates (${px}, ${py})` };
      }
      const evOpts = { clientX: px, clientY: py, bubbles: true, cancelable: true, view: window };
      targetEl.dispatchEvent(new MouseEvent('mousedown', evOpts));
      targetEl.dispatchEvent(new MouseEvent('mouseup', evOpts));
      targetEl.dispatchEvent(new MouseEvent('click', evOpts));
      await waitForDomQuiet(300, 3000);
      return { ok: true, coordinateClick: true, coords: [px, py] };
    }

    if (!action.target_id) {
      return { ok: false, error: `missing target_id for action ${action.action}` };
    }

    const el = idToEl.get(action.target_id);
    if (!el || !document.contains(el)) {
      return { ok: false, error: `unknown target_id: ${action.target_id}` };
    }

    // Element visible and non-zero size
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    if (r.width <= 0 || r.height <= 0 || s.visibility === 'hidden' || s.display === 'none') {
      return { ok: false, error: `element ${action.target_id} is not visible or has zero size` };
    }

    // Anti-honeypot checks (Task 2)
    const isOffscreen = r.left < -100 || r.top < -100 || r.left > window.innerWidth + 5000;
    const isZeroOpacity = s.opacity === '0' || parseFloat(s.opacity) < 0.05;
    const isHiddenAria = el.getAttribute('aria-hidden') === 'true' && el.tabIndex === -1;
    const isIndented = parseInt(s.textIndent, 10) < -1000;
    const isPointerBlocked = s.pointerEvents === 'none';

    if (isOffscreen || isZeroOpacity || isHiddenAria || isIndented || isPointerBlocked) {
      return { ok: false, error: `element ${action.target_id} detected as honeypot` };
    }

    // Form same-origin post verification (Task 2)
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
      await waitForDomQuiet(300, 3000);
      return { ok: true };
    }

    if (action.action === 'click') {
      el.scrollIntoView({ block: 'center', behavior: 'instant' });
      el.click();
      await waitForDomQuiet(300, 3000);
      return { ok: true };
    }

    if (action.action === 'select') {
      el.value = action.value;
      el.dispatchEvent(new Event('change', { bubbles: true }));
      await waitForDomQuiet(300, 3000);
      return { ok: true };
    }

    return { ok: false, error: `unsupported action: ${action.action}` };
  }

  api.runtime.onMessage.addListener((msg, _s, reply) => {
    if (msg?.type === 'PING') {
      reply({ ok: true });
      return false;
    }
    if (msg?.type === 'WAIT_QUIET') {
      waitForDomQuiet(300, 3000).then(() => reply({ ok: true }));
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

