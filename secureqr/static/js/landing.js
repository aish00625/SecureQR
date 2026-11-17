(function () {
  "use strict";
  const { api, showLoading, showError, showResults } = window.SecureQR;
  const form = document.getElementById("quick-form");
  const input = document.getElementById("quick-url");
  const out = document.getElementById("quick-result");

  async function check(url) {
    if (!url.trim()) { input.focus(); return; }
    out.classList.add("section-gap");
    showLoading(out, "Analysing link…");
    try {
      showResults(out, await api("/api/scan/url", { method: "POST", json: { url } }));
    } catch (e) { showError(out, e.message); }
    out.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  form.addEventListener("submit", (e) => { e.preventDefault(); check(input.value); });
  document.querySelectorAll(".chip[data-url]").forEach((c) => c.addEventListener("click", () => {
    input.value = c.dataset.url; check(c.dataset.url);
  }));
})();
