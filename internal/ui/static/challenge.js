(function () {
  var cfg = window.__g__ || window.__RG__ || {};
  var statusEl = document.getElementById("status");
  var subEl = document.getElementById("sub");
  var widget = document.getElementById("rg-widget");

  function setStatus(msg, working) {
    if (!statusEl) return;
    statusEl.textContent = msg;
    if (working) statusEl.classList.add("working");
    else statusEl.classList.remove("working");
  }

  function waitCaptcha() {
    if (!cfg.captcha) return Promise.resolve("");
    var input = document.getElementById("captcha");
    if (!input) return Promise.resolve("");
    if (subEl) subEl.textContent = "Complete the confirmation field.";
    return new Promise(function (resolve) {
      function check() {
        var v = (input.value || "").trim();
        if (v) resolve(v);
      }
      input.addEventListener("input", check);
      check();
    });
  }

  function nextURL() {
    try {
      var u = new URL(window.location.href);
      return u.searchParams.get("next") || "/";
    } catch (e) {
      return "/";
    }
  }

  async function submitPayload(payload, captcha) {
    var body = { payload: payload, ray: cfg.ray || "" };
    if (cfg.captcha) body.captcha = captcha || "";
    var res = await fetch((cfg.prefix || "/_rg") + "/challenge", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      var text = await res.text();
      throw new Error(text || "verify failed");
    }
    return res.json();
  }

  function arm() {
    if (!widget) {
      setStatus("Widget failed to load", false);
      return;
    }
    widget.addEventListener("statechange", function (ev) {
      var st = ev.detail && ev.detail.state;
      if (st === "verifying") setStatus("Working…", true);
      if (st === "verified") setStatus("Verified", false);
      if (st === "error") setStatus("Verification failed", false);
      if (st === "expired") setStatus("Challenge expired", false);
    });
    widget.addEventListener("verified", function (ev) {
      var payload = ev.detail && ev.detail.payload;
      waitCaptcha()
        .then(function (captcha) {
          return submitPayload(payload, captcha);
        })
        .then(function () {
          setStatus("Access granted", false);
          window.location.replace(nextURL());
        })
        .catch(function (err) {
          if (widget.reset) widget.reset("unverified");
          setStatus(String(err.message || err), false);
        });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", arm);
  } else {
    arm();
  }
})();
