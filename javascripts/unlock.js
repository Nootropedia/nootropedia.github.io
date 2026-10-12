// Unlocks the full text of paid pages on the public preview site.
// The build encrypts each paid page (AES-256-GCM, key from PBKDF2-SHA256 of
// the course password) into assets/locked/. Buyers enter the password on the
// Unlock page; the derived key is kept in this browser only.
(function () {
  "use strict";
  var STORE = "nootropics-course-key";
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function b64(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))); }
  function unb64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }

  function load() {
    try { return JSON.parse(localStorage.getItem(STORE) || "null"); } catch (e) { return null; }
  }
  function save(v) {
    try { v ? localStorage.setItem(STORE, JSON.stringify(v)) : localStorage.removeItem(STORE); } catch (e) { /* storage blocked */ }
  }

  async function getJSON(url) {
    var r = await fetch(url, { cache: "no-cache" });
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }
  async function deriveKey(password, meta) {
    var base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: unb64(meta.salt), iterations: meta.iterations, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  function importKey(raw) {
    return crypto.subtle.importKey("raw", unb64(raw), "AES-GCM", false, ["decrypt"]);
  }
  async function decrypt(key, box) {
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct));
    return dec.decode(pt);
  }

  // --- Unlock page -----------------------------------------------------------
  async function setupForm(form) {
    var metaUrl = form.getAttribute("data-meta");
    var msg = form.querySelector(".unlock-message");
    var input = form.querySelector("input[type=password]");
    function say(t) { msg.textContent = t; }
    var saved = load();
    if (saved) say("This browser is unlocked. Open any module to read the full text.");
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      say("Checking…");
      try {
        var meta = await getJSON(metaUrl);
        var key = await deriveKey(input.value.trim(), meta);
        if ((await decrypt(key, meta.check)) !== "ok") throw new Error("check");
        save({ salt: meta.salt, key: b64(await crypto.subtle.exportKey("raw", key)) });
        input.value = "";
        say("Unlocked. Open any module to read the full text.");
      } catch (e) {
        say(e && e.message === "404"
          ? "The full text is not available on this site yet."
          : "That password did not work. Check the purchase e-mail and try again.");
      }
    });
    var reset = form.querySelector(".unlock-forget");
    if (reset) reset.addEventListener("click", function () { save(null); say("This browser is locked again."); });
  }

  // --- Paid pages ------------------------------------------------------------
  async function unlockPage(marker) {
    var saved = load();
    if (!saved) return;
    try {
      var meta = await getJSON(marker.getAttribute("data-meta"));
      if (meta.salt !== saved.salt) { save(null); return; }   // password changed since
      var box = await getJSON(marker.getAttribute("data-src"));
      var html = await decrypt(await importKey(saved.key), box);
      var article = document.querySelector("article.md-content__inner");
      if (!article) return;
      article.innerHTML = html;
      document.documentElement.classList.add("course-unlocked");
      if (location.hash) {
        var target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
        if (target) target.scrollIntoView();
      }
    } catch (e) { /* stay on the teaser */ }
  }

  function init() {
    if (!window.crypto || !crypto.subtle) return;
    var form = document.getElementById("unlock-form");
    if (form) setupForm(form);
    var marker = document.getElementById("locked-page");
    if (marker) unlockPage(marker);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
