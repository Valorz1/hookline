// HookLine's page behaviour. Everything still works without it:
// this file only adds feedback and polish on top.

var calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
var MAX_BYTES = 10 * 1024 * 1024;  // the same 10 MB limit as app.py

// ---------- light / dark switch ----------
document.querySelectorAll(".theme-toggle").forEach(function (button) {
  button.addEventListener("click", function () {
    var root = document.documentElement;
    var isDark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = isDark ? "light" : "dark";
    try { localStorage.setItem("hookline-theme", root.dataset.theme); } catch (e) {}
  });
});

// ---------- the upload form (there can be more than one on a page) ----------
function niceSize(bytes) {
  if (bytes < 1024) return bytes + " bytes";
  if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

document.querySelectorAll(".upload").forEach(function (form) {
  var zone = form.querySelector(".dropzone");
  var input = zone.querySelector("input");
  var nameText = zone.querySelector(".file-name");
  var defaultText = nameText.textContent;

  // Highlight the drop zone while a file is dragged over it
  ["dragenter", "dragover"].forEach(function (type) {
    input.addEventListener(type, function () { zone.classList.add("dragging"); });
  });
  ["dragleave", "drop"].forEach(function (type) {
    input.addEventListener(type, function () { zone.classList.remove("dragging"); });
  });

  // Show which file was chosen, and catch the wrong kind before uploading
  function problemWith(file) {
    if (!file.name.toLowerCase().endsWith(".eml")) return "That isn't an .eml file";
    if (file.size > MAX_BYTES) return "That file is over 10 MB";
    return "";
  }

  function showFile() {
    var file = input.files[0];
    zone.classList.remove("has-file", "wrong-file");
    if (!file) {
      nameText.textContent = defaultText;
      return;
    }
    var problem = problemWith(file);
    zone.classList.add(problem ? "wrong-file" : "has-file");
    nameText.textContent = problem
      ? problem + ": " + file.name
      : file.name + " · " + niceSize(file.size);
  }
  input.addEventListener("change", showFile);

  // While the server works, swap the button for a progress bar with a timer.
  // The steps are what HookLine does, in order.
  var timer = null;
  form.addEventListener("submit", function (event) {
    var file = input.files[0];
    if (file && problemWith(file)) {
      event.preventDefault();
      zone.animate([{ translate: "-5px 0" }, { translate: "5px 0" }, { translate: "0 0" }], 300);
      return;
    }

    var label = form.querySelector(".progress-label");
    var clock = form.querySelector(".progress-time");
    // VirusTotal results arrive on the result page itself, so the wait here is short
    var steps = ["Reading the email", "Pulling out links and domains",
                 "Running 13 red-flag checks", "Adding up the score"];

    form.classList.add("busy");
    form.querySelector("button[type=submit]").disabled = true;

    var started = Date.now();
    var step = 0;
    timer = setInterval(function () {
      var seconds = Math.floor((Date.now() - started) / 1000);
      clock.textContent = Math.floor(seconds / 60) + ":" + String(seconds % 60).padStart(2, "0");
      // Move through the first steps quickly, then stay on the last one
      var next = Math.min(Math.floor((Date.now() - started) / 700), steps.length - 1);
      if (next !== step) {
        step = next;
        label.textContent = steps[step];
        label.classList.remove("in");
        void label.offsetWidth;  // restart the animation
        label.classList.add("in");
      }
    }, 100);
  });

  // Coming back with the Back button restores the old page from memory,
  // still in its "busy" state, so undo that
  window.addEventListener("pageshow", function (event) {
    if (!event.persisted) return;
    clearInterval(timer);
    form.classList.remove("busy");
    form.querySelector("button[type=submit]").disabled = false;
    showFile();
  });
});

// ---------- the changing words in the home page heading ----------
document.querySelectorAll(".rotator").forEach(function (rotator) {
  if (calm) return;
  var words = rotator.dataset.words.split("|");
  var index = 0;
  setInterval(function () {
    rotator.classList.remove("in");
    rotator.classList.add("out");
    setTimeout(function () {
      index = (index + 1) % words.length;
      rotator.textContent = words[index];
      rotator.classList.remove("out");
      rotator.classList.add("in");
    }, 350);
  }, 2800);
});

// ---------- count the score up (from zero, or from the old score) ----------
function countUp(counter, from) {
  var target = Number(counter.dataset.count);
  from = from || 0;
  if (calm || target === from) return;
  counter.textContent = from;
  var start = performance.now();
  var duration = 1200;
  function tick(now) {
    var t = Math.min((now - start) / duration, 1);
    var eased = 1 - Math.pow(1 - t, 4);
    counter.textContent = Math.round(from + (target - from) * eased);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
document.querySelectorAll("[data-count]").forEach(function (counter) { countUp(counter); });

// ---------- copy buttons for links, domains, hashes... ----------
// A function, so live VirusTotal rows can get buttons too
function addCopyButtons(area) {
  if (!navigator.clipboard) return;
  area.querySelectorAll("[data-copy]").forEach(function (item) {
    var value = item.textContent.trim();
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy-btn";
    button.setAttribute("aria-label", "Copy " + value);
    button.innerHTML =
      '<svg class="icon copy" aria-hidden="true"><use href="#copy"/></svg>' +
      '<svg class="icon done" aria-hidden="true"><use href="#check"/></svg>';
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(value).then(function () {
        button.classList.add("copied");
        setTimeout(function () { button.classList.remove("copied"); }, 1500);
      });
    });
    item.prepend(button);
  });
}
addCopyButtons(document);

// ---------- live VirusTotal results ----------
// The server pushes Server-Sent Events down one open connection: a "lookup"
// for each result (as a ready-made <li>), then "done" with the new verdict.
function htmlToElement(html) {
  var holder = document.createElement("template");
  holder.innerHTML = html.trim();
  return holder.content.firstElementChild;
}

document.querySelectorAll("[data-stream]").forEach(function (list) {
  var source = new EventSource(list.dataset.stream);

  // Each result replaces the first row still marked "Checking…"
  source.addEventListener("lookup", function (event) {
    var row = htmlToElement(JSON.parse(event.data));
    var pending = list.querySelector("li.pending");
    if (pending) pending.replaceWith(row); else list.append(row);
    row.classList.add("arrived");
    addCopyButtons(row);
  });

  source.addEventListener("done", function (event) {
    // Close it ourselves: otherwise EventSource reconnects when the server hangs up
    source.close();
    var data = JSON.parse(event.data);
    var oldScore = Number(document.querySelector("#result [data-count]").dataset.count);

    var verdict = htmlToElement(data.verdict);
    document.getElementById("result").replaceWith(verdict);
    document.getElementById("why-panel").replaceWith(htmlToElement(data.why));
    document.title = data.title;
    countUp(verdict.querySelector("[data-count]"), oldScore);
  });

  // "failed" is our own event (the analysis crashed); "error" is the browser's
  // (the connection dropped). Either way, stop and say so.
  function giveUp(message) {
    source.close();
    var note = document.querySelector(".live-note");
    if (note) {
      note.classList.add("stopped");
      note.lastChild.textContent = message;
    }
    list.querySelectorAll("li.pending .badge").forEach(function (badge) {
      badge.textContent = "Not checked";
    });
  }
  source.addEventListener("failed", function () {
    giveUp("VirusTotal checks stopped with an error. The verdict uses the quick checks only.");
  });
  source.addEventListener("error", function () {
    giveUp("Lost the connection to HookLine. Analyse the email again for VirusTotal results.");
  });
});
