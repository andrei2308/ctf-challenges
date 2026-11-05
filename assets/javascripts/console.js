/* =============================================================================
   Home page terminal. Progressive enhancement: with JS off the static readout
   in index.md stays on screen and every link on the page still works.
   ========================================================================== */
(function () {
  "use strict";

  // name -> [path relative to the site root, description]
  var PLACES = {
    "ctfs": ["ctfs/", "all CTF writeups"],
    "vuln-research": ["vulnerability-research/", "vulnerability research"],
    "achievements": ["achievements/", "results and rankings"],
    "whoami": ["whoami/", "about me"],
    "unbreakable2026": ["unbreakable2026/", "Unbreakable 2026"],
    "rocsc2026": ["rocsc2026/", "ROCSC 2026"],
    "htb-university2025": ["HackTheBox-University2025/", "HTB University CTF 2025"],
    "rocsc2025": ["rocsc2025/", "ROCSC 2025"],
    "ismctf2025": ["ismctf2025/", "ISM CTF 2025"],
    "hackthebox": ["HackTheBox/", "Hack The Box"],
    "cyberedu": ["cyberedu/", "CyberEDU"],
    "pwnable.kr": ["pwnable.kr/", "pwnable.kr"]
  };
  var TOP = ["ctfs", "vuln-research", "achievements", "whoami"];
  var EVENTS = Object.keys(PLACES).filter(function (k) { return TOP.indexOf(k) < 0; });

  function sGet(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }
  function sSet(k, v) { try { sessionStorage.setItem(k, v); } catch (e) {} }

  function init() {
    var screen = document.getElementById("term-screen");
    var form = document.getElementById("term-form");
    var input = document.getElementById("term-cmd");
    if (!screen || !form || !input || screen.dataset.ready) return;
    screen.dataset.ready = "1";

    var reduce = false;
    try { reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) {}
    var animate = !reduce && !sGet("term-booted");
    var skip = false;

    function line(cls) {
      var el = document.createElement("div");
      el.className = "term-line" + (cls ? " " + cls : "");
      screen.appendChild(el);
      screen.scrollTop = screen.scrollHeight;
      return el;
    }
    function emit(text, cls) { line(cls).textContent = text; }
    function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

    async function type(text, cls) {
      var el = line(cls);
      if (!animate || skip) { el.textContent = text; return; }
      for (var i = 0; i < text.length; i++) {
        el.textContent += text[i];
        await sleep(28 + Math.random() * 40);
        if (skip) { el.textContent = text; return; }
      }
    }

    var BOOT = [
      ["whoami", "term-cmd", true],
      ["andrei. ctf player, vulnerability researcher.", "", false],
      ["ls", "term-cmd", true],
      ["ctfs/  vuln-research/  achievements/  whoami/", "term-dir", false],
      ["type help to see what this can do.", "term-dim", false]
    ];

    function ready() {
      form.hidden = false;
      sSet("term-booted", "1");
    }

    function stop() { skip = true; }
    screen.addEventListener("click", stop, { once: true });

    (async function boot() {
      screen.innerHTML = "";
      for (var i = 0; i < BOOT.length; i++) {
        if (BOOT[i][2]) await type(BOOT[i][0], BOOT[i][1]);
        else emit(BOOT[i][0], BOOT[i][1]);
        if (animate && !skip) await sleep(BOOT[i][2] ? 260 : 120);
      }
      ready();
    })();

    function go(name) {
      var hit = PLACES[name];
      emit("opening " + hit[1] + " ...", "term-ok");
      setTimeout(function () { location.href = hit[0]; }, 220);
    }

    function match(arg) {
      arg = arg.replace(/\/+$/, "").replace(/^ctfs\//, "");
      if (PLACES[arg]) return arg;
      var hits = Object.keys(PLACES).filter(function (k) { return k.indexOf(arg) === 0; });
      return hits.length === 1 ? hits[0] : null;
    }

    var COMMANDS = {
      help: function () {
        emit("ls [ctfs]       list sections, or every event");
        emit("cd <name>       open a section or event   cd rocsc2026");
        emit("whoami          who writes this");
        emit("clear           clear the screen");
        emit("tab completes names, up/down walks history.", "term-dim");
      },
      ls: function (arg) {
        if (arg && arg.replace(/\/+$/, "") === "ctfs") {
          EVENTS.forEach(function (k) {
            var el = line();
            el.innerHTML = '<span class="term-dir"></span><span class="term-dim"></span>';
            el.firstChild.textContent = (k + "/").padEnd(22);
            el.lastChild.textContent = PLACES[k][1];
          });
          return;
        }
        if (arg) { emit("ls: " + arg + ": no such directory", "term-err"); return; }
        emit("ctfs/  vuln-research/  achievements/  whoami/", "term-dir");
      },
      cd: function (arg) {
        if (!arg || arg === "~" || arg === "/") { emit("already home.", "term-dim"); return; }
        var name = match(arg);
        if (!name) { emit("cd: no such directory: " + arg + "   (try ls ctfs)", "term-err"); return; }
        go(name);
      },
      whoami: function () {
        emit("andrei. ctf player, vulnerability researcher.");
        emit("web, reverse engineering, binary exploitation.", "term-dim");
      },
      cat: function (arg) {
        if (/flag/.test(arg || "")) { emit("cat: " + arg + ": nice try.", "term-err"); return; }
        emit("cat: " + (arg || "") + ": no such file", "term-err");
      },
      sudo: function () { emit("andrei is not in the sudoers file. this incident will be reported.", "term-err"); },
      clear: function () { screen.innerHTML = ""; }
    };
    COMMANDS.open = COMMANDS.cd;
    COMMANDS.dir = COMMANDS.ls;

    var history = [];
    var hpos = 0;

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var raw = input.value.trim();
      input.value = "";
      emit(raw, "term-cmd");
      if (!raw) return;
      history.push(raw);
      hpos = history.length;
      var bits = raw.split(/\s+/);
      var cmd = bits[0].toLowerCase();
      var arg = (bits[1] || "").toLowerCase();
      if (COMMANDS[cmd]) COMMANDS[cmd](arg);
      else emit(cmd + ": command not found   (try help)", "term-err");
      screen.scrollTop = screen.scrollHeight;
    });

    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowUp" && history.length) {
        e.preventDefault();
        hpos = Math.max(0, hpos - 1);
        input.value = history[hpos];
      } else if (e.key === "ArrowDown" && history.length) {
        e.preventDefault();
        hpos = Math.min(history.length, hpos + 1);
        input.value = history[hpos] || "";
      } else if (e.key === "Tab") {
        var m = input.value.match(/^(\s*(?:cd|open|ls)\s+)(\S*)$/i);
        var pool = m ? Object.keys(PLACES) : Object.keys(COMMANDS);
        var stem = m ? m[2].toLowerCase() : input.value.trim().toLowerCase();
        if (!stem && !m) return;
        var hits = pool.filter(function (k) { return k.indexOf(stem) === 0; });
        if (!hits.length) return;
        e.preventDefault();
        if (hits.length === 1) input.value = (m ? m[1] : "") + hits[0] + (m ? "" : " ");
        else emit(hits.join("  "), "term-dim");
      }
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
