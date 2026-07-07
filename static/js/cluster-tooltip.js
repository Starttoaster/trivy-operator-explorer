// cluster-tooltip.js renders a small, instant, theme-aware popover for any
// element carrying a `data-tooltip` attribute (the "N clusters" cells and the
// Pressure column header).
//
// It appends a single position:fixed element to <body> rather than using a
// CSS-only group-hover tooltip, because the tables live inside overflow-x-auto
// containers that also clip vertically and would cut the tooltip off. Values are
// rendered with pre-line whitespace: commas in a cluster list become separate
// lines, and long sentences wrap at the max width.
(function () {
  "use strict";

  let tip;
  const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function applyTheme() {
    if (!tip) return;
    if (darkQuery.matches) {
      tip.style.background = "rgba(17, 24, 39, 0.97)"; // gray-900
      tip.style.color = "#f9fafb"; // gray-50
      tip.style.border = "1px solid #374151"; // gray-700
      tip.style.boxShadow = "0 4px 12px rgba(0, 0, 0, 0.45)";
    } else {
      tip.style.background = "#ffffff";
      tip.style.color = "#111827"; // gray-900
      tip.style.border = "1px solid #e5e7eb"; // gray-200
      tip.style.boxShadow = "0 4px 12px rgba(0, 0, 0, 0.15)";
    }
  }

  function ensureTip() {
    if (tip) return tip;
    tip = document.createElement("div");
    Object.assign(tip.style, {
      position: "fixed",
      zIndex: "1000",
      pointerEvents: "none",
      padding: "6px 10px",
      borderRadius: "6px",
      fontSize: "12px",
      lineHeight: "1.45",
      whiteSpace: "pre-line",
      display: "none",
      maxWidth: "20rem",
    });
    document.body.appendChild(tip);
    applyTheme();
    return tip;
  }

  darkQuery.addEventListener("change", applyTheme);

  function show(el) {
    const raw = el.getAttribute("data-tooltip");
    if (!raw) return;
    const t = ensureTip();
    applyTheme();
    // A comma-separated value (e.g. a cluster list) renders one item per line;
    // a plain sentence is left as-is and wrapped by pre-line + max-width.
    if (raw.indexOf(",") !== -1) {
      t.textContent = raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean).join("\n");
    } else {
      t.textContent = raw;
    }
    t.style.display = "block";
    position(el);
  }

  function position(el) {
    if (!tip) return;
    const r = el.getBoundingClientRect();
    const pad = 8;
    let top = r.bottom + 6;
    let left = r.left;
    if (left + tip.offsetWidth > window.innerWidth - pad) {
      left = window.innerWidth - tip.offsetWidth - pad;
    }
    if (top + tip.offsetHeight > window.innerHeight - pad) {
      top = r.top - tip.offsetHeight - 6;
    }
    tip.style.left = Math.max(pad, left) + "px";
    tip.style.top = Math.max(pad, top) + "px";
  }

  function hide() {
    if (tip) tip.style.display = "none";
  }

  document.addEventListener("mouseover", function (e) {
    const el = e.target.closest("[data-tooltip]");
    if (el) show(el);
  });

  document.addEventListener("mouseout", function (e) {
    const el = e.target.closest("[data-tooltip]");
    if (el && !el.contains(e.relatedTarget)) hide();
  });

  window.addEventListener("scroll", hide, true);
})();
