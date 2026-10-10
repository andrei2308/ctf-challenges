/* =============================================================================
   operator console — global status bar + landing terminal
   Progressive enhancement: everything here is additive. With JS off, the page
   still renders real card links and prose.
   ========================================================================== */
(function () {
  "use strict";

  var SECTIONS = [
    ["vuln-research", "vulnerability-research/", "Vulnerability Research"],
    ["rocsc2026", "rocsc2026/", "ROCSC 2026"],
    ["unbreakable2026", "unbreakable2026/", "Unbreakable 2026"],
    ["hackthebox", "HackTheBox/", "Hack The Box"],
    ["htb-university", "HackTheBox-University2025/", "HTB University 2025"],
    ["cyberedu", "cyberedu/", "CyberEDU"],
    ["pwnable.kr", "pwnable.kr/", "pwnable.kr"],
    ["rocsc2025", "rocsc2025/", "ROCSC 2025"],
    ["repository", "repository/", "Repository"]
  ];

  function safeGet(k) {
    try { return localStorage.getItem(k); } catch (e) { return null; }
  }
  function safeSet(k, v) {
    try { localStorage.setItem(k, v); } catch (e) {}
  }

  /* ---- base path (works at / locally and /ctf-challenges/ on Pages) ------ */
  function rootRelative(href) {
    // index page lives at the site root; links are already root-relative.
    return href;
  }

  /* ---------------------------------------------------------------- theme - */
  function currentScheme() {
    return document.body.getAttribute("data-md-color-scheme") || "slate";
  }
  function toggleTheme() {
    try {
      var labels = document.querySelectorAll('label[for^="__palette_"]');
      for (var i = 0; i < labels.length; i++) {
        if (labels[i].offsetParent !== null) { labels[i].click(); return; }
      }
    } catch (e) {}
  }

  /* -------------------------------------------------------------- scanlines */
  function applyScan(on) {
    document.documentElement.classList.toggle("scan", !!on);
  }

  /* ------------------------------------------------------------ status bar - */
  function breadcrumb() {
    var p = location.pathname.replace(/index\.html$/, "").replace(/\/$/, "");
    var parts = p.split("/").filter(Boolean);
    if (parts[0] === "ctf-challenges") parts.shift();
    return "~" + (parts.length ? "/" + parts.join("/") : "");
  }

  function buildStatusBar() {
    if (document.querySelector(".hud-statusbar")) return;
    var bar = document.createElement("div");
    bar.className = "hud-statusbar";
    bar.setAttribute("role", "contentinfo");

    var scanOn = safeGet("hud-scan") === "1";
    applyScan(scanOn);

    bar.innerHTML =
      '<span class="hud-seg hud-seg--mode">ONLINE</span>' +
      '<span class="hud-seg hud-seg--host">andrei@ctf</span>' +
      '<span class="hud-seg hud-seg--path">' + breadcrumb() + "</span>" +
      '<span class="hud-spacer"></span>' +
      '<button type="button" class="hud-seg hud-seg--btn" data-act="scan">SCAN:' +
        (scanOn ? "ON" : "OFF") + "</button>" +
      '<button type="button" class="hud-seg hud-seg--btn" data-act="theme">THEME:' +
        (currentScheme() === "default" ? "LIGHT" : "DARK") + "</button>" +
      '<span class="hud-seg hud-seg--clock" data-role="clock">--:--:-- UTC</span>';

    document.body.appendChild(bar);
    document.documentElement.classList.add("has-statusbar");

    bar.addEventListener("click", function (e) {
      var t = e.target.closest("[data-act]");
      if (!t) return;
      var act = t.getAttribute("data-act");
      if (act === "scan") {
        var now = !document.documentElement.classList.contains("scan");
        applyScan(now);
        safeSet("hud-scan", now ? "1" : "0");
        t.textContent = "SCAN:" + (now ? "ON" : "OFF");
      } else if (act === "theme") {
        toggleTheme();
        setTimeout(function () {
          t.textContent = "THEME:" + (currentScheme() === "default" ? "LIGHT" : "DARK");
        }, 60);
      }
    });

    var clock = bar.querySelector('[data-role="clock"]');
    function tick() {
      var d = new Date();
      function z(n) { return (n < 10 ? "0" : "") + n; }
      clock.textContent =
        z(d.getUTCHours()) + ":" + z(d.getUTCMinutes()) + ":" + z(d.getUTCSeconds()) + " UTC";
    }
    tick();
    setInterval(tick, 1000);
  }

  /* --------------------------------------------------------------- terminal */
  function initTerminal() {
    var screen = document.getElementById("term-screen");
    var form = document.getElementById("term-form");
    var input = document.getElementById("term-cmd");
    if (!screen || !form || !input) return;
    if (screen.dataset.booted) return; // run once per page load
    screen.dataset.booted = "1";

    var reduce = false;
    try {
      reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    } catch (e) {}

    function line(cls) {
      var el = document.createElement("div");
      el.className = "term-line" + (cls ? " " + cls : "");
      screen.appendChild(el);
      screen.scrollTop = screen.scrollHeight;
      return el;
    }
    function emit(text, cls) {
      var el = line(cls);
      el.textContent = text;
      return el;
    }

    function sleep(ms) {
      return new Promise(function (r) { setTimeout(r, ms); });
    }

    var skip = false;
    function onSkip() { skip = true; }
    document.addEventListener("keydown", onSkip, { once: true });
    screen.addEventListener("click", onSkip, { once: true });

    async function type(text, cls) {
      var el = line(cls);
      if (reduce || skip) { el.textContent = text; return; }
      for (var i = 0; i < text.length; i++) {
        el.textContent += text[i];
        screen.scrollTop = screen.scrollHeight;
        await sleep(text[i] === " " ? 6 : 10);
      }
    }

    var BOOT = [
      ["andrei@ctf:~/security-research$ ./boot", "term-cmdline"],
      ["[ 0.001 ] initializing operator console ............. ok", "term-ok"],
      ["[ 0.014 ] mounting /writeups ................ 85 entries ok", "term-ok"],
      ["[ 0.027 ] tracks: pwn rev web crypto forensics osint .. ok", "term-ok"],
      ["[ 0.041 ] vuln-research ................. 1 CVE published", "term-ok"],
      ["[ 0.055 ] link established // phosphor green", "term-dim"]
    ];

    function ready() {
      emit("ready. type `help` for commands, or scroll to browse.", "term-ready");
      form.hidden = false;
      try { input.focus({ preventScroll: true }); } catch (e) { input.focus(); }
    }

    (async function boot() {
      screen.innerHTML = ""; // clear the static (no-JS) fallback readout
      for (var i = 0; i < BOOT.length; i++) {
        await type(BOOT[i][0], BOOT[i][1]);
        if (!reduce && !skip) await sleep(80);
      }
      ready();
    })();

    /* ---- commands --------------------------------------------------------- */
    var COMMANDS = {
      help: function () {
        emit("available commands:", "term-head");
        emit("  help            this message");
        emit("  whoami          who runs this console");
        emit("  ls              list sections");
        emit("  open <section>  jump to a section   e.g. open rocsc2026");
        emit("  theme           toggle light / dark");
        emit("  scan            toggle CRT scanlines");
        emit("  date            current UTC time");
        emit("  clear           clear the screen");
      },
      whoami: function () {
        emit("andrei — security researcher & ctf operator.", "term-accent");
        emit("pwn · rev · web · crypto · forensics · osint.");
      },
      ls: function () {
        SECTIONS.forEach(function (s) {
          var el = line();
          el.innerHTML =
            '<span class="term-dir">' + s[0] + "/</span>" +
            '<span class="term-dim">   ' + s[2] + "</span>";
        });
      },
      open: function (arg) {
        if (!arg) { emit("usage: open <section>  (try `ls`)", "term-err"); return; }
        var hit = SECTIONS.filter(function (s) {
          return s[0] === arg || s[0].indexOf(arg) === 0;
        })[0];
        if (!hit) { emit("no such section: " + arg + "  (try `ls`)", "term-err"); return; }
        emit(">>> opening " + hit[2] + " ...", "term-accent");
        setTimeout(function () { location.href = rootRelative(hit[1]); }, 260);
      },
      theme: function () {
        toggleTheme();
        emit(">>> theme toggled.", "term-accent");
      },
      scan: function () {
        var now = !document.documentElement.classList.contains("scan");
        applyScan(now);
        safeSet("hud-scan", now ? "1" : "0");
        emit(">>> scanlines " + (now ? "enabled" : "disabled") + ".", "term-accent");
        var btn = document.querySelector('.hud-seg--btn[data-act="scan"]');
        if (btn) btn.textContent = "SCAN:" + (now ? "ON" : "OFF");
      },
      date: function () { emit(new Date().toUTCString()); },
      clear: function () { screen.innerHTML = ""; },
      sudo: function () { emit("nice try.", "term-err"); }
    };

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var raw = input.value.trim();
      input.value = "";
      emit("$ " + raw, "term-cmdline");
      if (!raw) return;
      var bits = raw.split(/\s+/);
      var cmd = bits[0].toLowerCase();
      var arg = bits[1] ? bits[1].toLowerCase() : "";
      if (COMMANDS[cmd]) COMMANDS[cmd](arg);
      else emit("command not found: " + cmd + "   (try `help`)", "term-err");
      screen.scrollTop = screen.scrollHeight;
    });
  }

  function init() {
    buildStatusBar();
    initTerminal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Re-run on Material's instant-navigation page swaps, if enabled.
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(function () {
      var bar = document.querySelector(".hud-statusbar");
      if (bar) {
        var path = bar.querySelector(".hud-seg--path");
        if (path) path.textContent = breadcrumb();
      } else {
        buildStatusBar();
      }
      initTerminal();
    });
  }
})();
