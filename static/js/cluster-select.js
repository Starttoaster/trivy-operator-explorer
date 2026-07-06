// cluster-select.js powers the multi-cluster selector in the sidebar.
//
// The frontend reads report bundles from an S3 bucket that many clusters write
// into. This script:
//   1. populates the selector from GET /api/v1/clusters,
//   2. reflects the current ?cluster= query param as the selected option,
//   3. reloads the current page with the chosen cluster when changed, and
//   4. rewrites internal links so the selected cluster is preserved as the user
//      navigates around the UI.
//
// An empty value means "All clusters" (aggregate mode).
(function () {
  "use strict";

  function currentCluster() {
    return new URLSearchParams(window.location.search).get("cluster") || "";
  }

  // Rewrite same-origin, path-based links to carry the current cluster so
  // navigation preserves the selection without threading it through every
  // server-side template.
  function propagateClusterToLinks(cluster) {
    if (!cluster) return;
    document.querySelectorAll('a[href^="/"]').forEach(function (a) {
      const href = a.getAttribute("href");
      // Skip static assets and already-parameterized cluster links.
      if (href.startsWith("/static/")) return;
      try {
        const url = new URL(href, window.location.origin);
        if (!url.searchParams.has("cluster")) {
          url.searchParams.set("cluster", cluster);
          a.setAttribute("href", url.pathname + url.search + url.hash);
        }
      } catch (e) {
        /* ignore malformed hrefs */
      }
    });
  }

  function onChange(select) {
    const url = new URL(window.location.href);
    if (select.value) {
      url.searchParams.set("cluster", select.value);
    } else {
      url.searchParams.delete("cluster");
    }
    window.location.href = url.toString();
  }

  document.addEventListener("DOMContentLoaded", function () {
    const select = document.getElementById("clusterSelect");
    if (!select) return;

    const selected = currentCluster();
    propagateClusterToLinks(selected);

    fetch("/api/v1/clusters")
      .then(function (resp) {
        return resp.ok ? resp.json() : [];
      })
      .then(function (clusters) {
        (clusters || []).forEach(function (name) {
          const opt = document.createElement("option");
          opt.value = name;
          opt.textContent = name;
          if (name === selected) opt.selected = true;
          select.appendChild(opt);
        });
        // Ensure the "All clusters" option is selected when no cluster is set.
        if (!selected) select.value = "";
      })
      .catch(function () {
        /* leave the selector with just the All clusters option */
      });

    select.addEventListener("change", function () {
      onChange(select);
    });
  });
})();
