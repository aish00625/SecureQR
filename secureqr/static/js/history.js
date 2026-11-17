(function () {
  "use strict";
  const { api, el, badge, localTime, toast, pct } = window.SecureQR;
  const rows = document.getElementById("rows");
  const count = document.getElementById("count");
  const prev = document.getElementById("prev");
  const next = document.getElementById("next");
  const LIMIT = 25;
  let offset = 0;

  const SOURCE = { upload: "Image", webcam: "Camera", url: "Link" };

  function message(text) { rows.replaceChildren(el("tr", {}, el("td", { colspan: 7, class: "muted" }, text))); }

  async function load() {
    const q = document.getElementById("q").value.trim();
    const risk = document.getElementById("risk").value;
    const params = new URLSearchParams({ limit: LIMIT, offset });
    if (q) params.set("q", q);
    if (risk) params.set("risk", risk);
    try {
      const data = await api(`/api/history?${params}`);
      if (!data.items.length) {
        message(offset || q || risk ? "No scans match these filters." : el("span", {}, "No scans yet. ", el("a", { href: "/scan" }, "Scan your first QR code")));
      } else {
        rows.replaceChildren(...data.items.map((s) => el("tr", {},
          el("td", { class: "num", text: localTime(s.created_at) }),
          el("td", { text: SOURCE[s.source] || s.source }),
          el("td", { class: "content-cell", title: s.raw_content, text: s.raw_content }),
          el("td", { text: s.ml_label ? `${s.ml_label === "PHISHING" ? "Phishing" : "Legit"} ${pct(s.ml_probability)}` : "–" }),
          el("td", { class: "num", text: s.heuristic_score ?? "–" }),
          el("td", {}, badge(s.risk_level)),
          el("td", {}, el("a", { href: `/history/${s.id}` }, "View")))));
      }
      const end = Math.min(offset + LIMIT, data.total);
      count.textContent = data.total ? `${offset + 1}–${end} of ${data.total}` : "";
      prev.disabled = offset === 0;
      next.disabled = end >= data.total;
    } catch (e) { message(e.message); }
  }

  document.getElementById("filters").addEventListener("submit", (e) => { e.preventDefault(); offset = 0; load(); });
  document.getElementById("risk").addEventListener("change", () => { offset = 0; load(); });
  prev.addEventListener("click", () => { offset = Math.max(0, offset - LIMIT); load(); });
  next.addEventListener("click", () => { offset += LIMIT; load(); });
  document.getElementById("clear-all").addEventListener("click", async () => {
    if (!window.confirm("Delete all scan history? This cannot be undone.")) return;
    try { const r = await api("/api/history", { method: "DELETE" }); toast(`Deleted ${r.deleted} scans`); offset = 0; load(); }
    catch (e) { toast(e.message); }
  });
  load();
})();
