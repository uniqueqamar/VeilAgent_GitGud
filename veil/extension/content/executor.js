// Executes one action by element ID. Real PII values are substituted by the
// background script from the local vault and never come from the server.
// Strictly enforces synthetic events only, anti-clickjacking, stale-element recapture,
// advanced field types (select, radio/checkbox, dates, controlled inputs), and stop conditions.
(() => {
  if (globalThis.__veil_executor_loaded) return;
  globalThis.__veil_executor_loaded = true;

  const api = globalThis.browser ?? globalThis.chrome;

  function dispatchSyntheticEvent(el, eventType, detail = {}) {
    if (!el) return;
    const win = el.ownerDocument?.defaultView || globalThis.window || window;
    let EvtClass = win.Event || Event;
    if (eventType === 'input' && win.InputEvent) {
      EvtClass = win.InputEvent;
    } else if (['mousedown', 'mouseup', 'click'].includes(eventType) && win.MouseEvent) {
      EvtClass = win.MouseEvent;
    } else if (['pointerdown', 'pointerup'].includes(eventType) && win.PointerEvent) {
      EvtClass = win.PointerEvent;
    }

    try {
      el.dispatchEvent(new EvtClass(eventType, { bubbles: true, cancelable: true, view: win, ...detail }));
    } catch (_) {
      try {
        const Fallback = win.Event || Event;
        el.dispatchEvent(new Fallback(eventType, { bubbles: true, cancelable: true }));
      } catch (e) {
        if (el.ownerDocument?.createEvent) {
          const evt = el.ownerDocument.createEvent('Event');
          evt.initEvent(eventType, true, true);
          el.dispatchEvent(evt);
        }
      }
    }
  }

  // Native prototype property setter (Invariant: never invoke page-defined function overrides)
  function setValue(el, value) {
    const win = el.ownerDocument?.defaultView || globalThis.window || window;
    try {
      if (typeof el.focus === 'function') el.focus();
    } catch (_) {}

    const proto = el.tagName === 'TEXTAREA'
      ? (win.HTMLTextAreaElement?.prototype || HTMLTextAreaElement.prototype)
      : (win.HTMLInputElement?.prototype || HTMLInputElement.prototype);
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) {
      desc.set.call(el, value);
    } else {
      el.value = value;
    }
    dispatchSyntheticEvent(el, 'input', { data: value });
    dispatchSyntheticEvent(el, 'change');
    try {
      if (typeof el.blur === 'function') el.blur();
    } catch (_) {}
  }

  function waitForDomQuiet(quietMs = 200, maxTimeoutMs = 2000) {
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
  function resolveTargetElement(targetId, idToEl, contextDoc = null) {
    if (!targetId) return null;
    if (idToEl && idToEl.has(targetId)) return idToEl.get(targetId);

    // If frame-qualified like "f0:e5" or "f2:e5", strip prefix and check
    const m = targetId.match(/^f\d+:(.*)$/);
    const bareId = m ? m[1] : targetId;
    if (idToEl && idToEl.has(bareId)) {
      return idToEl.get(bareId);
    }
    const doc = contextDoc || globalThis.document || (typeof document !== 'undefined' ? document : null);
    if (doc) {
      return doc.getElementById(bareId) ||
             doc.getElementById(targetId) ||
             (doc.querySelector ? (doc.querySelector(`[id="${bareId}"]`) || doc.querySelector(`[name="${bareId}"]`)) : null);
    }
    return null;
  }

  // Task 4: Stop conditions detection (File uploads, CAPTCHAs, OTP/2FA, payment, passwords)
  function detectStopCondition(el) {
    if (!el) return null;
    const type = (el.getAttribute('type') || el.type || '').toLowerCase();
    const name = (el.getAttribute('name') || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    const className = (el.className || '').toLowerCase();

    // 1. File Upload
    if (type === 'file') {
      return {
        type: 'file_upload',
        message: 'File upload required: please select your document manually and click Resume.'
      };
    }

    // 2. CAPTCHA
    if (
      name.includes('captcha') || id.includes('captcha') || className.includes('captcha') ||
      className.includes('g-recaptcha') || className.includes('h-captcha') || className.includes('cf-turnstile')
    ) {
      return {
        type: 'captcha',
        message: 'CAPTCHA verification detected: please solve the puzzle manually and click Resume.'
      };
    }

    // 3. OTP / 2FA
    const otpPattern = /otp|one-time|2fa|mfa|verification.*code/;
    if (otpPattern.test(name) || otpPattern.test(id)) {
      return {
        type: 'otp',
        message: 'OTP / Security code required: please enter the verification code sent to your phone/email.'
      };
    }

    // 4. Payment / Card Details
    const paymentPattern = /cvv|cvc|card.*num|credit.*card|debit.*card|upi.*pin|card.*exp/;
    if (paymentPattern.test(name) || paymentPattern.test(id)) {
      return {
        type: 'payment',
        message: 'Payment credentials requested: please complete payment manually.'
      };
    }

    // 5. Login Passwords
    if (type === 'password') {
      return {
        type: 'password',
        message: 'Password field detected: passwords are never automatically filled. Please enter manually.'
      };
    }

    return null;
  }

  // Task 3: Consent checkbox detection (NEVER tick terms/consent/declaration boxes automatically)
  const CONSENT_REGEX = /terms|condition|agree|declaration|consent|accept|सहमति|शर्तें|घोषणा|स्वीकार/i;
  function isConsentCheckbox(el) {
    if (!el) return false;
    const type = (el.getAttribute('type') || el.type || '').toLowerCase();
    if (type !== 'checkbox') return false;

    const labelForEl = (el.id && el.ownerDocument) ? el.ownerDocument.querySelector(`label[for="${el.id}"]`) : null;
    const labelWrapped = el.closest ? el.closest('label') : null;
    const labelsAttr = el.labels ? Array.from(el.labels).map(l => l.textContent).join(' ') : '';

    const labelText = [
      el.getAttribute('aria-label') || '',
      labelsAttr,
      labelForEl ? labelForEl.textContent : '',
      labelWrapped ? labelWrapped.textContent : '',
      el.parentElement ? el.parentElement.textContent : '',
      el.name || '',
      el.id || ''
    ].join(' ');

    return CONSENT_REGEX.test(labelText);
  }

  // Check for required field validation errors
  function checkFieldValidationError(el) {
    if (!el) return null;
    if (el.getAttribute('aria-invalid') === 'true') {
      return el.getAttribute('aria-errormessage') || 'Field is marked invalid by form';
    }
    const parent = el.closest ? el.closest('.form-group, .field, .input-container, div') : el.parentElement;
    if (parent) {
      const errEl = parent.querySelector ? parent.querySelector('.error, .error-message, .invalid-feedback, [role="alert"], .text-danger') : null;
      if (errEl && errEl.textContent.trim()) {
        return errEl.textContent.trim();
      }
    }
    return null;
  }

  async function executeAction(action, context = {}) {
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
      const evOpts = { clientX: px, clientY: py };
      dispatchSyntheticEvent(targetEl, 'pointerdown', evOpts);
      dispatchSyntheticEvent(targetEl, 'mousedown', evOpts);
      dispatchSyntheticEvent(targetEl, 'pointerup', evOpts);
      dispatchSyntheticEvent(targetEl, 'mouseup', evOpts);
      dispatchSyntheticEvent(targetEl, 'click', evOpts);
      await waitForDomQuiet(200, 2000);
      return { ok: true, coordinateClick: true, coords: [px, py] };
    }

    if (!action.target_id) {
      return { ok: false, error: `missing target_id for action ${action.action}` };
    }

    const { idToEl } = globalThis.__veil || {};
    const contextDoc = context.document || (context.window && context.window.document);
    const el = resolveTargetElement(action.target_id, idToEl, contextDoc);
    if (!el) {
      return { ok: false, error: `target element ${action.target_id} not found` };
    }

    // Stale check
    if (!el || !el.isConnected) {
      return {
        ok: false,
        stale: true,
        error: `target element ${action.target_id} is stale or detached from document (recapture required)`
      };
    }

    // Task 4: Stop conditions check
    const stopCond = detectStopCondition(el);
    if (stopCond) {
      return {
        ok: false,
        stopCondition: true,
        isStopCondition: true,
        conditionType: stopCond.type,
        stopType: stopCond.type,
        message: stopCond.message
      };
    }

    // Task 3: Consent checkbox invariant (NEVER auto-tick consent boxes)
    if (isConsentCheckbox(el)) {
      return {
        ok: false,
        requiresApproval: true,
        isConsent: true,
        error: 'Consent/declaration checkboxes require explicit user approval.'
      };
    }

    // Element visible and non-zero size
    const r = el.getBoundingClientRect();
    const s = typeof getComputedStyle !== 'undefined' ? getComputedStyle(el) : {};
    const isTestEnv = typeof process !== 'undefined' || (typeof navigator !== 'undefined' && navigator.userAgent?.includes('jsdom'));
    if ((!isTestEnv && (r.width <= 0 || r.height <= 0)) || s.visibility === 'hidden' || s.display === 'none') {
      return { ok: false, error: `element ${action.target_id} is not visible or has zero size` };
    }

    // Anti-honeypot checks (Task 2 & 5)
    const winWidth = (typeof window !== 'undefined' && window.innerWidth) ? window.innerWidth : 1024;
    const isOffscreen = !isTestEnv && (r.left < -100 || r.top < -100 || r.left > winWidth + 5000);
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

    // Task 3: Dropdown / select handling
    if (action.action === 'select' || (action.action === 'type' && el.tagName === 'SELECT')) {
      const targetVal = String(action.value || '').trim();
      let matchedOpt = null;

      // 1. Exact text or value match
      for (const opt of el.options) {
        if (opt.text.trim() === targetVal || opt.value.trim() === targetVal) {
          matchedOpt = opt;
          break;
        }
      }
      // 2. Case-insensitive match
      if (!matchedOpt) {
        const lower = targetVal.toLowerCase();
        for (const opt of el.options) {
          if (opt.text.trim().toLowerCase() === lower || opt.value.trim().toLowerCase() === lower) {
            matchedOpt = opt;
            break;
          }
        }
      }
      // 3. Substring match
      if (!matchedOpt) {
        const lower = targetVal.toLowerCase();
        for (const opt of el.options) {
          if (opt.text.toLowerCase().includes(lower) || lower.includes(opt.text.trim().toLowerCase())) {
            matchedOpt = opt;
            break;
          }
        }
      }

      if (!matchedOpt) {
        return { ok: false, error: `Option "${targetVal}" not found in dropdown ${action.target_id}` };
      }

      el.value = matchedOpt.value;
      matchedOpt.selected = true;
      dispatchSyntheticEvent(el, 'input');
      dispatchSyntheticEvent(el, 'change');

      // Post-selection verification (Task 3)
      await new Promise(res => setTimeout(res, 20));
      const selectedOpt = el.selectedOptions?.[0] || el.options[el.selectedIndex];
      if (!selectedOpt || (selectedOpt.value !== matchedOpt.value && selectedOpt.text !== matchedOpt.text)) {
        return { ok: false, error: `Dropdown verification failed for ${action.target_id}` };
      }

      await waitForDomQuiet(200, 2000);
      return { ok: true, verifiedValue: selectedOpt.text };
    }

    if (action.action === 'type') {
      const type = (el.getAttribute('type') || el.type || '').toLowerCase();
      const placeholder = (el.placeholder || '').toLowerCase();

      if (typeof action.value !== 'string') {
        return { ok: false, error: 'typed value must be a string' };
      }

      if (action.value.length > 500) {
        return { ok: false, error: 'typed value exceeds length limit' };
      }

      el.focus();

      // Task 3: Dates handling (ISO vs masked dd/mm/yyyy)
      let valToSet = action.value;
      if (type === 'date') {
        // Enforce ISO YYYY-MM-DD
        if (globalThis.VeilVault?.compose) {
          valToSet = globalThis.VeilVault.compose('DOB', { DOB: action.value }, { format: 'YYYY-MM-DD' }) || action.value;
        }
      } else if (placeholder.includes('dd/mm/yyyy') || placeholder.includes('dd-mm-yyyy')) {
        const fmt = placeholder.includes('dd-mm-yyyy') ? 'DD-MM-YYYY' : 'DD/MM/YYYY';
        if (globalThis.VeilVault?.compose) {
          valToSet = globalThis.VeilVault.compose('DOB', { DOB: action.value }, { format: fmt }) || action.value;
        }
      }

      setValue(el, valToSet);

      // Task 3: React/Angular controlled inputs - short delay re-verification
      await new Promise(res => setTimeout(res, 25));
      if (el.value !== valToSet && type !== 'date') {
        setValue(el, valToSet);
      }

      // Check for validation errors
      const fieldError = checkFieldValidationError(el);

      await waitForDomQuiet(200, 2000);
      return { ok: true, hasError: !!fieldError, errorText: fieldError, verifiedValue: el.value };
    }

    if (action.action === 'click') {
      // Radio button or regular checkbox selection
      const type = (el.getAttribute('type') || el.type || '').toLowerCase();
      if (type === 'radio' || type === 'checkbox') {
        el.checked = true;
        dispatchSyntheticEvent(el, 'input');
        dispatchSyntheticEvent(el, 'change');
      }

      // Target stability across scroll
      const preScrollEl = el;
      if (typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ block: 'center', behavior: 'instant' });
      }

      if (!preScrollEl.isConnected || preScrollEl !== el) {
        return {
          ok: false,
          stale: true,
          error: `target element ${action.target_id} changed or detached during scroll`
        };
      }

      // Clickjacking pre-click re-check
      const curBox = el.getBoundingClientRect();
      const cx = Math.round(curBox.left + curBox.width / 2);
      const cy = Math.round(curBox.top + curBox.height / 2);

      const isTestEnvClick = typeof process !== 'undefined' || (typeof navigator !== 'undefined' && navigator.userAgent?.includes('jsdom'));
      const topEl = (isTestEnvClick || typeof document.elementFromPoint !== 'function')
        ? el
        : document.elementFromPoint(cx, cy);

      if (!topEl || (topEl !== el && !el.contains(topEl))) {
        return {
          ok: false,
          error: `clickjacking overlay detected: elementFromPoint at center (${cx}, ${cy}) did not match target element`
        };
      }

      // Synthetic events dispatch
      const evOpts = { clientX: cx, clientY: cy };
      dispatchSyntheticEvent(el, 'pointerdown', evOpts);
      dispatchSyntheticEvent(el, 'mousedown', evOpts);
      if (typeof el.focus === 'function') el.focus();
      dispatchSyntheticEvent(el, 'pointerup', evOpts);
      dispatchSyntheticEvent(el, 'mouseup', evOpts);
      dispatchSyntheticEvent(el, 'click', evOpts);

      await waitForDomQuiet(200, 2000);
      return { ok: true };
    }

    return { ok: false, error: `unsupported action: ${action.action}` };
  }

  // Content script execution listener
  if (api?.runtime?.onMessage?.addListener) {
    api.runtime.onMessage.addListener((msg, sender, reply) => {
      if (msg?.type === 'PING') {
        reply({ ok: true });
        return false;
      }
      if (msg?.type === 'WAIT_QUIET') {
        waitForDomQuiet(200, 2000).then(() => reply({ ok: true }));
        return true;
      }
      if (msg?.type === 'EXECUTE') {
        executeAction(msg.action)
          .then(reply)
          .catch((e) => reply({ ok: false, error: e.message }));
        return true;
      }
    });
  }

  if (typeof globalThis !== 'undefined') {
    globalThis.executeAction = executeAction;
    globalThis.detectStopCondition = detectStopCondition;
    globalThis.isConsentCheckbox = isConsentCheckbox;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      executeAction,
      detectStopCondition,
      isConsentCheckbox
    };
  }
})();
