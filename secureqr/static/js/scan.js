(function () {
  "use strict";
  const { api, showLoading, showError, showResults, toast } = window.SecureQR;
  const result = document.getElementById("result");

  /* ---------- tabs (WAI-ARIA tab pattern) ---------- */
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  function select(tab) {
    tabs.forEach((t) => {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
    if (tab.id !== "tab-camera") stopCamera();
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) { const n = tabs[(i + d + tabs.length) % tabs.length]; n.focus(); select(n); }
    });
  });

  /* ---------- upload ---------- */
  const MAX_MB = Number(document.getElementById("dropzone").dataset.maxMb || 5);
  const MAX = MAX_MB * 1024 * 1024;
  const ALLOWED = ["png", "jpg", "jpeg", "webp", "bmp"];
  const drop = document.getElementById("dropzone");
  const input = document.getElementById("file-input");
  const preview = document.getElementById("preview");
  const img = document.getElementById("preview-img");
  let current = null;

  function pick(file) {
    if (!file) return;
    const ext = (file.name.split(".").pop() || "").toLowerCase();
    if (!ALLOWED.includes(ext)) { showError(result, "Unsupported file type. Use PNG, JPG, WEBP or BMP."); return; }
    if (file.size > MAX) { showError(result, `File is too large (max ${MAX_MB} MB).`); return; }
    current = file;
    if (img.src) URL.revokeObjectURL(img.src);
    img.src = URL.createObjectURL(file);
    preview.classList.add("is-visible");
    drop.hidden = true;
  }
  input.addEventListener("change", () => pick(input.files[0]));
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("is-over"); }));
  drop.addEventListener("drop", (e) => pick(e.dataTransfer.files[0]));
  document.addEventListener("paste", (e) => {
    const f = [...(e.clipboardData?.files || [])][0];
    if (f) { select(document.getElementById("tab-upload")); pick(f); }
  });
  document.getElementById("clear-btn").addEventListener("click", () => {
    current = null; input.value = ""; preview.classList.remove("is-visible"); drop.hidden = false;
  });
  const uploadBtn = document.getElementById("upload-btn");
  uploadBtn.addEventListener("click", async () => {
    if (!current) return;
    const fd = new FormData();
    fd.append("file", current, current.name);
    uploadBtn.disabled = true;
    showLoading(result, "Decoding QR code and analysing content…");
    try { showResults(result, await api("/api/scan/image", { method: "POST", body: fd })); }
    catch (e) { showError(result, e.message); }
    finally { uploadBtn.disabled = false; }
  });

  /* ---------- camera ---------- */
  const video = document.getElementById("video");
  const idle = document.getElementById("camera-idle");
  const frame = document.getElementById("camera-frame");
  const pulse = document.getElementById("cam-pulse");
  const status = document.getElementById("cam-status");
  const startBtn = document.getElementById("cam-start");
  const stopBtn = document.getElementById("cam-stop");
  const canvas = document.createElement("canvas");
  let stream = null, timer = null, busy = false;

  function setStatus(text, on) { status.textContent = text; pulse.classList.toggle("on", !!on); }

  async function startCamera() {
    if (!navigator.mediaDevices?.getUserMedia) {
      setStatus("Camera access needs a modern browser on http://localhost or HTTPS.", false); return;
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
    } catch (e) {
      setStatus(e.name === "NotAllowedError" ? "Camera permission was denied. Allow it in the browser's site settings." : "No camera could be started.", false);
      return;
    }
    video.srcObject = stream;
    await video.play();
    idle.hidden = true; frame.hidden = false;
    startBtn.disabled = true; stopBtn.disabled = false;
    setStatus("Looking for a QR code…", true);
    timer = setInterval(grab, 700);
  }

  function stopCamera() {
    clearInterval(timer); timer = null;
    if (stream) stream.getTracks().forEach((t) => t.stop());
    stream = null; video.srcObject = null;
    idle.hidden = false; frame.hidden = true;
    startBtn.disabled = false; stopBtn.disabled = true;
    setStatus("Camera off", false);
  }

  async function grab() {
    if (busy || !stream || video.readyState < 2) return;
    busy = true;
    const w = video.videoWidth, h = video.videoHeight;
    const scale = Math.min(1, 960 / Math.max(w, h));
    canvas.width = Math.round(w * scale); canvas.height = Math.round(h * scale);
    canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.85));
    try {
      const fd = new FormData();
      fd.append("file", blob, "frame.jpg");
      const data = await api("/api/scan/frame", { method: "POST", body: fd });
      if (data && data.found) {
        stopCamera();
        setStatus("QR code found. Camera stopped.", false);
        showResults(result, data);
        toast("QR code detected");
      }
    } catch (e) {
      if (e.status === 429) setStatus("Scanning too fast, slowing down…", true);
      else { stopCamera(); showError(result, e.message); }
    } finally { busy = false; }
  }
  startBtn.addEventListener("click", startCamera);
  stopBtn.addEventListener("click", stopCamera);
  window.addEventListener("pagehide", stopCamera);

  /* ---------- url ---------- */
  document.getElementById("url-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = document.getElementById("url-input").value;
    if (!v.trim()) { showError(result, "Enter a link to check."); return; }
    showLoading(result, "Analysing link…");
    try { showResults(result, await api("/api/scan/url", { method: "POST", json: { url: v } })); }
    catch (err) { showError(result, err.message); }
  });
})();
