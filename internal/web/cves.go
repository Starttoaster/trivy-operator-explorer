package web

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/cve"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/source"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
)

// parseCVEParams extracts the cluster selector and CVE list filters shared by
// the HTML and JSON CVE handlers.
func parseCVEParams(r *http.Request) (cluster string, params cve.Params) {
	q := r.URL.Query()
	cluster = q.Get("cluster")

	var hasFix *bool
	if raw := q.Get("hasfix"); raw != "" {
		if v, err := strconv.ParseBool(raw); err == nil {
			hasFix = &v
		} else {
			log.Logger.Warn("could not parse hasfix query parameter to bool type, ignoring filter", "raw", raw, "error", err.Error())
		}
	}

	limit := 0
	if raw := q.Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			limit = v
		}
	}

	return cluster, cve.Params{
		Severity:    q.Get("severity"),
		HasFix:      hasFix,
		Class:       q.Get("class"),
		PackageType: q.Get("package_type"),
		CVEID:       q.Get("cve"),
		ShowIgnored: parseBoolQuery("showignored", q.Get("showignored")),
		SortBy:      q.Get("sort_by"),
		Limit:       limit,
	}
}

// cvesHandler renders the cluster-wide CVE triage page.
func cvesHandler(w http.ResponseWriter, r *http.Request) {
	funcMap := template.FuncMap{
		"sanitizeID": func(s string) string {
			replacer := strings.NewReplacer("/", "_", ":", "_", " ", "_", "-", "_", ".", "_")
			return replacer.Replace(s)
		},
	}

	tmpl := template.Must(template.New("cves.html").Funcs(funcMap).ParseFS(content.Static, "static/cves.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing cves html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	cluster, params := parseCVEParams(r)
	reports, err := source.GetVulnerabilityReportList(cluster)
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}

	result := cve.List(reports, params)

	hasFix := ""
	if params.HasFix != nil {
		hasFix = strconv.FormatBool(*params.HasFix)
	}

	templateData := struct {
		PageRoute   string
		Cluster     string
		Result      cve.Result
		Severity    string
		Class       string
		HasFix      string
		ShowIgnored bool
		SortBy      string
	}{
		PageRoute:   "cves",
		Cluster:     cluster,
		Result:      result,
		Severity:    params.Severity,
		Class:       params.Class,
		HasFix:      hasFix,
		ShowIgnored: params.ShowIgnored,
		SortBy:      params.SortBy,
	}

	if err := tmpl.Execute(w, templateData); err != nil {
		log.Logger.Error("encountered error executing cves html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

// apiCvesHandler is the JSON counterpart to the /cves page.
func apiCvesHandler(w http.ResponseWriter, r *http.Request) {
	cluster, params := parseCVEParams(r)
	reports, err := source.GetVulnerabilityReportList(cluster)
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerability reports")
		return
	}
	writeJSON(w, http.StatusOK, cve.List(reports, params))
}
