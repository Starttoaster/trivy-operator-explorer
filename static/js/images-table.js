// images-table.js adds client-side search and CSV export to the /images table.

function filterImages(query) {
  "use strict";
  const q = (query || "").trim().toLowerCase();
  let visible = 0;
  document.querySelectorAll("#imagesTable tbody tr.image-row").forEach(function (row) {
    const hay = (row.getAttribute("data-search") || "").toLowerCase();
    const match = q === "" || hay.indexOf(q) !== -1;
    row.classList.toggle("hidden", !match);
    if (match) visible++;
    // Hide the (normally collapsed) resources sub-row when its image is filtered out.
    const digest = row.getAttribute("data-digest");
    if (digest && !match) {
      const sub = document.getElementById("resources-" + digest);
      if (sub) sub.classList.add("hidden");
    }
  });
}

// setImageClass reloads the page with the chosen package-class filter, preserving
// other query params (cluster, hasfix, showignored, ...).
function setImageClass(value) {
  "use strict";
  const url = new URL(window.location.href);
  if (value) {
    url.searchParams.set("class", value);
  } else {
    url.searchParams.delete("class");
  }
  window.location.href = url.toString();
}

function exportImages(event) {
  "use strict";
  if (event) event.preventDefault();
  const headers = ["Image", "Cluster", "OS", "Fixable", "Total", "Critical", "High", "Medium", "Low"];
  const lines = [headers.join(",")];

  document.querySelectorAll("#imagesTable tbody tr.image-row").forEach(function (row) {
    if (row.classList.contains("hidden")) return;
    const get = function (k) { return (row.getAttribute("data-" + k) || "").trim(); };
    const values = [
      get("name"), get("cluster"), get("os"), get("fixable"),
      get("total"), get("critical"), get("high"), get("medium"), get("low"),
    ].map(imgCsvEscape);
    lines.push(values.join(","));
  });

  imgDownloadCSV("images.csv", lines.join("\n"));
}

function imgCsvEscape(s) {
  "use strict";
  s = (s || "").replace(/\s+/g, " ").trim();
  if (/[",\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function imgDownloadCSV(filename, text) {
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
