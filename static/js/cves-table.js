// cves-table.js powers the /cves triage table: expandable per-CVE rows, a
// client-side search box, and CSV export of the currently-visible rows.

function toggleCVE(id) {
  "use strict";
  const detail = document.getElementById("detail-" + id);
  const icon = document.getElementById("icon-" + id);
  if (!detail) return;
  detail.classList.toggle("hidden");
  if (icon) {
    icon.style.transform = detail.classList.contains("hidden") ? "rotate(0deg)" : "rotate(180deg)";
  }
}

function filterCVEs(query) {
  "use strict";
  const q = (query || "").trim().toLowerCase();
  const rows = document.querySelectorAll("#cvesTable tbody tr.cve-row");
  let visible = 0;
  rows.forEach(function (row) {
    const hay = (row.getAttribute("data-search") || "").toLowerCase();
    const match = q === "" || hay.indexOf(q) !== -1;
    row.classList.toggle("hidden", !match);
    if (match) visible++;
    // Keep each row's detail sub-row hidden while filtering to avoid orphans.
    const id = row.querySelector("[id^='icon-']");
    if (id) {
      const detailID = "detail-" + id.id.replace(/^icon-/, "");
      const detail = document.getElementById(detailID);
      if (detail && !match) detail.classList.add("hidden");
    }
  });
  const counter = document.getElementById("cveCount");
  if (counter) counter.textContent = String(visible);
}

function exportCVEs(event) {
  "use strict";
  if (event) event.preventDefault();
  const headers = ["CVE", "Severity", "Score", "Fix", "Class", "Images", "Pressure"];
  const lines = [headers.join(",")];

  document.querySelectorAll("#cvesTable tbody tr.cve-row").forEach(function (row) {
    if (row.classList.contains("hidden")) return;
    const cells = row.querySelectorAll("th, td");
    const values = [];
    cells.forEach(function (c) {
      values.push(csvEscape(c.textContent.trim().replace(/\s+/g, " ")));
    });
    lines.push(values.join(","));
  });

  downloadCSV("cves.csv", lines.join("\n"));
}

function csvEscape(s) {
  "use strict";
  if (/[",\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function downloadCSV(filename, text) {
  "use strict";
  const blob = new Blob([text], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
