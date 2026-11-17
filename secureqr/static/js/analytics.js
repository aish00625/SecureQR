(function () {
  "use strict";
  const { api, el, svg, badge } = window.SecureQR;
  const COLORS = { HIGH: "var(--high)", MEDIUM: "var(--medium)", LOW: "var(--low)" };

  function daily(container, days) {
    const W = 560, H = 220, P = { l: 30, r: 8, t: 10, b: 26 };
    const max = Math.max(1, ...days.map((d) => d.LOW + d.MEDIUM + d.HIGH));
    const bw = (W - P.l - P.r) / days.length;
    const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Stacked bar chart of scans per day by risk level" });
    const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
    [0, 0.5, 1].forEach((f) => {
      const v = Math.round(max * f);
      s.append(svg("line", { x1: P.l, x2: W - P.r, y1: y(v), y2: y(v), stroke: "var(--line)", "stroke-width": 1 }));
      const t = svg("text", { x: P.l - 6, y: y(v) + 4, "text-anchor": "end", fill: "var(--faint)", "font-size": 11 }); t.textContent = v; s.append(t);
    });
    days.forEach((d, i) => {
      let base = 0;
      for (const k of ["LOW", "MEDIUM", "HIGH"]) {
        if (!d[k]) continue;
        const rect = svg("rect", { x: P.l + i * bw + 3, width: Math.max(2, bw - 6), y: y(base + d[k]), height: y(base) - y(base + d[k]), fill: COLORS[k], rx: 2 });
        const title = svg("title", {}); title.textContent = `${d.day}: ${d[k]} ${k.toLowerCase()}`; rect.append(title);
        s.append(rect); base += d[k];
      }
      if (i % 2 === 0 || days.length <= 7) {
        const t = svg("text", { x: P.l + i * bw + bw / 2, y: H - 8, "text-anchor": "middle", fill: "var(--faint)", "font-size": 11 });
        t.textContent = d.day.slice(5); s.append(t);
      }
    });
    container.replaceChildren(s);
  }

  function hbars(container, items, empty) {
    if (!items.length) { container.replaceChildren(el("p", { class: "muted small", text: empty })); return; }
    const max = Math.max(...items.map((i) => i.value));
    container.replaceChildren(...items.map((i) => {
      const fill = el("span"); fill.style.width = `${(i.value / max) * 100}%`;
      return el("div", { class: "hbar" }, el("span", { text: i.label }), el("div", { class: "hbar-track" }, fill), el("span", { class: "num muted", text: i.value }));
    }));
  }

  api("/api/stats").then((s) => {
    document.getElementById("s-total").textContent = s.total;
    document.getElementById("s-high").textContent = s.by_risk.HIGH;
    document.getElementById("s-medium").textContent = s.by_risk.MEDIUM;
    document.getElementById("s-low").textContent = s.by_risk.LOW;
    daily(document.getElementById("daily-chart"), s.daily);
    hbars(document.getElementById("findings-chart"), s.top_findings.map((f) => ({ label: f.title, value: f.count })), "No warnings recorded yet.");
    hbars(document.getElementById("source-chart"), [["Image upload", s.by_source.upload], ["Camera", s.by_source.webcam], ["Pasted link", s.by_source.url]]
      .map(([label, value]) => ({ label, value })).filter((x) => x.value), "No scans yet.");
    const ht = document.getElementById("hosts-table");
    if (!s.top_hosts.length) ht.replaceChildren(el("p", { class: "muted small", text: "No domains scanned yet." }));
    else ht.replaceChildren(el("div", { class: "table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", { text: "Host" }), el("th", { class: "num", text: "Scans" }), el("th", { text: "Highest risk" }))),
      el("tbody", {}, s.top_hosts.map((h) => el("tr", {}, el("td", { class: "content-cell", text: h.host }), el("td", { class: "num", text: h.count }), el("td", {}, badge(h.max_risk))))))));
  }).catch((e) => {
    document.getElementById("daily-chart").replaceChildren(el("div", { class: "alert alert-error", text: e.message }));
  });
})();
