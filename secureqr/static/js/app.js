/* SecureQR shared front-end helpers.
 * Security note: all scanned/user-controlled content is inserted with
 * textContent (never innerHTML) and scanned URLs are never rendered as links. */
(function () {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function svg(tag, attrs) {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    return n;
  }

  async function api(path, options = {}) {
    const opts = { credentials: "same-origin", ...options };
    opts.headers = { "X-CSRF-Token": csrf, Accept: "application/json", ...(options.headers || {}) };
    if (options.json !== undefined) {
      opts.body = JSON.stringify(options.json);
      opts.headers["Content-Type"] = "application/json";
      delete opts.json;
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      throw new Error("Cannot reach the SecureQR server. Check that it is still running.");
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON */ }
    if (!res.ok && !(data && data.found === false)) {
      const err = new Error((data && data.message) || `Request failed (${res.status}).`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  let toastTimer;
  function toast(msg) {
    const t = document.getElementById("toast");
    if (!t) return;
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
  }

  const RISK_TEXT = { HIGH: "High risk", MEDIUM: "Medium risk", LOW: "Low risk" };
  const RISK_VALUE = { HIGH: 0.9, MEDIUM: 0.55, LOW: 0.18 };
  const RISK_COLOR = { HIGH: "var(--high)", MEDIUM: "var(--medium)", LOW: "var(--low)" };

  function riskDial(level) {
    const s = svg("svg", { viewBox: "0 0 80 80", class: "risk-dial", "aria-hidden": "true" });
    const r = 32, c = 2 * Math.PI * r;
    s.append(svg("circle", { cx: 40, cy: 40, r, fill: "none", stroke: "var(--ink-3)", "stroke-width": 8 }));
    const arc = svg("circle", {
      cx: 40, cy: 40, r, fill: "none", stroke: RISK_COLOR[level], "stroke-width": 8, "stroke-linecap": "round",
      "stroke-dasharray": `${c * RISK_VALUE[level]} ${c}`, transform: "rotate(-90 40 40)",
    });
    s.append(arc);
    const icon = svg("path", {
      d: level === "LOW" ? "M31 40l6 6 12-13" : level === "MEDIUM" ? "M40 29v14M40 50v1" : "M32 32l16 16M48 32 32 48",
      fill: "none", stroke: RISK_COLOR[level], "stroke-width": 4, "stroke-linecap": "round", "stroke-linejoin": "round",
    });
    s.append(icon);
    return s;
  }

  function badge(level) {
    return el("span", { class: `badge badge-${level}`, text: RISK_TEXT[level] || level });
  }

  function pct(x) { return `${(x * 100).toFixed(1)}%`; }
  function tone(level) { return { HIGH: "high", MEDIUM: "medium", LOW: "low" }[level]; }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard"), () => toast("Copy failed"));
    } else {
      toast("Clipboard is not available here");
    }
  }

  function mlPanel(ml) {
    const head = el("div", { class: "signal-head" }, el("h4", { text: "Machine learning" }), el("span", { class: "signal-kind", text: "Statistical prediction" }));
    if (!ml) {
      return el("div", { class: "signal" }, head, el("p", { class: "muted small", text: "Not applicable: this content type is not sent to the URL model." }));
    }
    if (!ml.available) {
      return el("div", { class: "signal" }, head, el("p", { class: "tone-medium small", text: "Model unavailable. " + (ml.error || "") }));
    }
    const p = ml.phishing_probability;
    const level = p >= 0.8 ? "HIGH" : p >= 0.5 ? "MEDIUM" : "LOW";
    const bar = el("span", { class: `bg-${tone(level)}` });
    bar.style.width = pct(p);
    return el("div", { class: "signal" }, head,
      el("div", { class: `signal-value tone-${tone(level)}`, text: ml.label === "PHISHING" ? "Phishing" : "Legitimate" }),
      el("div", { class: "meter", role: "img", "aria-label": `Phishing probability ${pct(p)}` }, bar),
      el("div", { class: "small muted" }, `Phishing probability ${pct(p)} · threshold ${pct(ml.threshold)}`),
      el("div", { class: "small muted", text: ml.model }));
  }

  function heuristicPanel(h) {
    const head = el("div", { class: "signal-head" }, el("h4", { text: "Security rules" }), el("span", { class: "signal-kind", text: "Deterministic checks" }));
    if (!h) return el("div", { class: "signal" }, head, el("p", { class: "muted small", text: "No link to analyse." }));
    const level = h.score >= 50 ? "HIGH" : h.score >= 20 ? "MEDIUM" : "LOW";
    const bar = el("span", { class: `bg-${tone(level)}` });
    bar.style.width = `${h.score}%`;
    const n = h.findings.length;
    return el("div", { class: "signal" }, head,
      el("div", { class: `signal-value tone-${tone(level)}` }, `${h.score}`, el("span", { class: "small muted", text: " / 100" })),
      el("div", { class: "meter", role: "img", "aria-label": `Heuristic score ${h.score} of 100` }, bar),
      el("div", { class: "small muted", text: n ? `${n} warning${n > 1 ? "s" : ""} raised` : "No warnings raised" }));
  }

  function renderResult(r) {
    const level = r.risk_level;
    const head = el("div", { class: "verdict-head" }, riskDial(level),
      el("div", {},
        el("p", { class: "risk-title", text: RISK_TEXT[level] }),
        el("ul", { class: "risk-reasons" }, r.risk_reasons.map((x) => el("li", { text: x })))));

    const body = el("div", { class: "verdict-body" });

    // Payload / URL (displayed as text only - never a hyperlink)
    const shown = r.url || r.raw_content;
    const payload = el("div", { class: "payload" },
      el("div", { class: "payload-row" },
        el("span", { text: r.content_label + (r.url ? " · not opened" : "") }),
        el("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => copyText(shown) }, "Copy")),
      el("div", { class: "payload-url", text: shown || "(empty)" }),
      r.url_defanged ? el("div", { class: "payload-defanged", title: "Safe-to-share (defanged) form", text: r.url_defanged }) : null);
    body.append(payload);

    if (r.url || r.ml) body.append(el("div", { class: "split" }, mlPanel(r.ml), heuristicPanel(r.heuristics)));

    if (r.heuristics && r.heuristics.findings.length) {
      body.append(el("div", {},
        el("p", { class: "section-label", text: "Why this was flagged" }),
        el("ul", { class: "findings" }, r.heuristics.findings.map((f) =>
          el("li", { class: "finding", "data-sev": f.severity },
            el("span", { class: "finding-bar" }),
            el("div", {}, el("strong", { text: f.title }), el("span", { text: f.detail })),
            el("span", { class: "finding-pts", title: "Points added to the rule score", text: `+${f.points}` }))))));
    }

    if (r.heuristics) {
      const fx = r.heuristics.facts;
      const kv = [["Domain", fx.registered_domain || "–"], ["Host", fx.host || "–"], ["HTTPS", fx.https ? "Yes" : "No"],
        ["Subdomains", String(fx.subdomain_count)], ["IP address host", fx.is_ip ? "Yes" : "No"], ["Length", `${fx.length} chars`]];
      body.append(el("div", {}, el("p", { class: "section-label", text: "URL details" }),
        el("dl", { class: "kv" }, kv.map(([k, v]) => el("div", {}, el("dt", { text: k }), el("dd", { text: v }))))));
    }

    const det = r.content_details || {};
    const detKeys = Object.keys(det).filter((k) => det[k]);
    if (detKeys.length) {
      body.append(el("div", {}, el("p", { class: "section-label", text: "Decoded fields" }),
        el("dl", { class: "kv" }, detKeys.map((k) => el("div", {}, el("dt", { text: k.replace(/_/g, " ") }), el("dd", { text: String(det[k]) }))))));
    }

    if (r.content_notes && r.content_notes.length) {
      body.append(el("div", {}, el("p", { class: "section-label", text: "Notes" }), el("ul", { class: "notes" }, r.content_notes.map((n) => el("li", { text: n })))));
    }
    body.append(el("div", {}, el("p", { class: "section-label", text: "What to do" }), el("ul", { class: "notes" }, r.recommendations.map((n) => el("li", { text: n })))));

    const foot = el("div", { class: "verdict-foot" },
      el("span", { text: r.decoder ? `Decoded with ${r.decoder}` : "Entered manually" }),
      r.id ? el("a", { href: `/history/${encodeURIComponent(r.id)}` }, `Saved as scan #${r.id}`) : null);

    return el("article", { class: "verdict", "data-risk": level }, head, body, foot);
  }

  function showLoading(container, text) {
    container.replaceChildren(el("div", { class: "panel loading" }, el("span", { class: "spinner", "aria-hidden": "true" }), el("span", { text })));
  }
  function showError(container, message) {
    container.replaceChildren(el("div", { class: "alert alert-error", role: "alert" }, el("strong", { text: "Scan failed." }), el("span", { text: message })));
  }
  function showResults(container, data) {
    if (!data || !data.found) {
      container.replaceChildren(el("div", { class: "alert alert-info", role: "status" }, el("strong", { text: "No QR code found." }), el("span", { text: (data && data.message) || "" })));
      return;
    }
    container.replaceChildren(...data.results.map(renderResult));
  }

  function localTime(iso) {
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  // mobile nav
  const toggle = document.querySelector(".nav-toggle");
  if (toggle) toggle.addEventListener("click", () => {
    const nav = document.getElementById("site-nav");
    const open = nav.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });
  document.querySelectorAll("[data-local-time]").forEach((t) => { t.textContent = localTime(t.getAttribute("datetime")); });

  window.SecureQR = { el, svg, api, toast, badge, renderResult, showLoading, showError, showResults, localTime, pct };
})();
