(function () {
  var cfg = window.__RG__ || {};
  var statusEl = document.getElementById("status");
  var subEl = document.getElementById("sub");
  var interacted = false;

  function setStatus(msg, working) {
    if (!statusEl) return;
    statusEl.textContent = msg;
    if (working) statusEl.classList.add("working");
    else statusEl.classList.remove("working");
  }

  function markInteracted() {
    interacted = true;
  }

  function armInteraction() {
    window.addEventListener("pointerdown", markInteracted, { once: true, passive: true });
    window.addEventListener("keydown", markInteracted, { once: true, passive: true });
    window.addEventListener("touchstart", markInteracted, { once: true, passive: true });
  }

  function waitInteraction(ms) {
    if (interacted) return Promise.resolve();
    if (subEl) subEl.textContent = "Move your mouse or press a key to continue.";
    return new Promise(function (resolve) {
      var done = false;
      function finish() {
        if (done) return;
        done = true;
        markInteracted();
        resolve();
      }
      window.addEventListener("pointerdown", finish, { once: true, passive: true });
      window.addEventListener("keydown", finish, { once: true, passive: true });
      window.addEventListener("touchstart", finish, { once: true, passive: true });
      setTimeout(function () {
        if (done) return;
        done = true;
        resolve();
      }, ms);
    });
  }

  function collectEnv(solveMs) {
    var plugins = 0;
    try {
      plugins = navigator.plugins ? navigator.plugins.length : 0;
    } catch (e) {
      plugins = 0;
    }
    var headless = false;
    try {
      if (/HeadlessChrome/i.test(String(navigator.userAgent || ""))) headless = true;
      if (navigator.webdriver) headless = headless || false;
    } catch (e) {}
    var playwright = false;
    try {
      if (window.__playwright || window.__pwInitScripts || window._playwright) playwright = true;
    } catch (e) {}
    return {
      webdriver: !!(navigator.webdriver),
      playwright: playwright,
      headless: headless,
      no_plugins: plugins === 0,
      interacted: !!interacted || !!(document.hasFocus && document.hasFocus()),
      solve_ms: solveMs | 0
    };
  }

  function sha256(buf) {
    return crypto.subtle.digest("SHA-256", buf).then(function (hash) {
      return new Uint8Array(hash);
    });
  }

  function leadingZeroBits(bytes) {
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      var c = bytes[i];
      if (c === 0) {
        n += 8;
        continue;
      }
      for (var b = 7; b >= 0; b--) {
        if ((c & (1 << b)) === 0) n++;
        else return n;
      }
    }
    return n;
  }

  function encodeU64BE(n) {
    var out = new Uint8Array(8);
    var x = BigInt(n);
    for (var i = 7; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function concat(a, b, c) {
    var out = new Uint8Array(a.length + b.length + c.length);
    out.set(a, 0);
    out.set(b, a.length);
    out.set(c, a.length + b.length);
    return out;
  }

  async function solve(nonce, difficulty) {
    var enc = new TextEncoder();
    var prefix = enc.encode(nonce + ":");
    var i = 0;
    while (i < 4294967295) {
      var hash = await sha256(concat(prefix, encodeU64BE(i), new Uint8Array(0)));
      if (leadingZeroBits(hash) >= difficulty) return String(i);
      i++;
      if ((i & 1023) === 0) await new Promise(function (r) { setTimeout(r, 0); });
    }
    throw new Error("pow failed");
  }

  function captchaValue() {
    if (!cfg.captcha) return "";
    var el = document.getElementById("captcha");
    return el ? String(el.value || "").trim() : "";
  }

  async function waitCaptcha() {
    if (!cfg.captcha) return;
    setStatus("Complete the check below", false);
    if (subEl) subEl.textContent = "Enter the confirmation text, then continue.";
    return new Promise(function (resolve) {
      var el = document.getElementById("captcha");
      if (!el) {
        resolve();
        return;
      }
      function done() {
        if (captchaValue()) resolve();
      }
      el.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") done();
      });
      el.focus();
      var t = setInterval(function () {
        if (captchaValue()) {
          clearInterval(t);
          resolve();
        }
      }, 250);
    });
  }

  async function run() {
    armInteraction();
    setStatus("Verifying you are human", true);
    try {
      await waitCaptcha();
      await waitInteraction(400);
      setStatus("Verifying you are human", true);
      var parts = String(cfg.token || "").split(".");
      var nonce = parts[0];
      var difficulty = cfg.difficulty | 0;
      var t0 = performance.now();
      var solution = await solve(nonce, difficulty);
      var solveMs = Math.max(1, Math.round(performance.now() - t0));
      setStatus("Redirecting", true);
      var payload = {
        token: cfg.token,
        solution: solution,
        ray: cfg.ray,
        env: collectEnv(solveMs)
      };
      if (cfg.captcha) payload.captcha = captchaValue();
      var res = await fetch((cfg.prefix || "/_rg") + "/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        var t = await res.text();
        throw new Error(t || "challenge failed");
      }
      var next = new URLSearchParams(location.search).get("next") || "/";
      location.replace(next);
    } catch (e) {
      setStatus("Verification failed", false);
      if (subEl) subEl.textContent = String(e && e.message ? e.message : e);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }
})();
