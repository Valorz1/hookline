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
  // The steps are what HookLine does, in order. Without VirusTotal it's done
  // in under a second; with it, nearly all the wait is VirusTotal.
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
    var steps = ["Reading the email", "Pulling out links and domains", "Running 13 red-flag checks"];
    steps.push(form.elements.virustotal.checked
      ? "Asking VirusTotal, about 15 s per lookup"
      : "Adding up the score");

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

// ---------- count the score up from zero ----------
document.querySelectorAll("[data-count]").forEach(function (counter) {
  var target = Number(counter.dataset.count);
  if (calm || !target) return;
  var start = performance.now();
  var duration = 1200;
  function tick(now) {
    var t = Math.min((now - start) / duration, 1);
    var eased = 1 - Math.pow(1 - t, 4);
    counter.textContent = Math.round(target * eased);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
});

// ---------- copy buttons for links, domains, hashes... ----------
if (navigator.clipboard) {
  document.querySelectorAll("[data-copy]").forEach(function (item) {
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
