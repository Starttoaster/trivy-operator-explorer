package mcp

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	"github.com/starttoaster/trivy-operator-explorer/internal/cve"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/source"
)

// listCVEsParams encodes every filter understood by the list_cves MCP tool.
// All fields are optional; the zero value returns every CVE in the cluster
// sorted by pressure_desc.
type listCVEsParams struct {
	Cluster     string `json:"cluster,omitempty" jsonschema:"optional cluster name to scope results to; empty means aggregate across all clusters"`
	Severity    string `json:"severity,omitempty" jsonschema:"optional severity filter (critical|high|medium|low), case-insensitive"`
	HasFix      *bool  `json:"has_fix,omitempty" jsonschema:"when true return only CVEs with a fixed version available; when false return only those without"`
	Class       string `json:"class,omitempty" jsonschema:"optional Trivy package class filter (typically 'os-pkgs' or 'lang-pkgs'), case-insensitive exact match"`
	PackageType string `json:"package_type,omitempty" jsonschema:"optional package type filter (e.g. 'apk', 'dpkg', 'gobinary', 'npm'), case-insensitive exact match"`
	CVEID       string `json:"cve_id,omitempty" jsonschema:"optional exact CVE ID filter (case-insensitive) to look up a single CVE"`
	ShowIgnored bool   `json:"show_ignored,omitempty" jsonschema:"when true include CVE occurrences that are marked as ignored in the database"`
	SortBy      string `json:"sort_by,omitempty" jsonschema:"sort order: 'pressure_desc' (default, score * affected_images), 'score_desc', 'affected_count_desc', or 'cve_id_asc'"`
	Limit       int    `json:"limit,omitempty" jsonschema:"maximum number of CVEs to return; 0 means no limit"`
}

// listCVEsResult is the typed response of the list_cves MCP tool.
type listCVEsResult = cve.Result

// runListCVEs is the shared implementation behind the list_cves MCP tool.
func runListCVEs(reports *v1alpha1.VulnerabilityReportList, p listCVEsParams) listCVEsResult {
	return cve.List(reports, cve.Params{
		Severity:    p.Severity,
		HasFix:      p.HasFix,
		Class:       p.Class,
		PackageType: p.PackageType,
		CVEID:       p.CVEID,
		ShowIgnored: p.ShowIgnored,
		SortBy:      p.SortBy,
		Limit:       p.Limit,
	})
}

// listImagesWithCVEParams encodes the inputs to the list_images_with_cve MCP
// tool. CVEID is required; Severity is an optional defensive filter.
type listImagesWithCVEParams struct {
	Cluster     string `json:"cluster,omitempty" jsonschema:"optional cluster name to scope results to; empty means aggregate across all clusters"`
	CVEID       string `json:"cve_id" jsonschema:"required CVE ID to look up (e.g. 'CVE-2023-1234'), case-insensitive"`
	Severity    string `json:"severity,omitempty" jsonschema:"optional severity filter (critical|high|medium|low), case-insensitive"`
	ShowIgnored bool   `json:"show_ignored,omitempty" jsonschema:"when true include occurrences that are marked as ignored in the database"`
}

// listImagesWithCVEResult is the typed response for list_images_with_cve.
type listImagesWithCVEResult struct {
	CVE   *cve.Aggregate `json:"cve,omitempty"`
	Found bool           `json:"found"`
}

func runListImagesWithCVE(reports *v1alpha1.VulnerabilityReportList, p listImagesWithCVEParams) listImagesWithCVEResult {
	agg, found := cve.ListImagesWithCVE(reports, p.CVEID, p.Severity, p.ShowIgnored)
	return listImagesWithCVEResult{CVE: agg, Found: found}
}

// getReportsOrError loads the vulnerability reports for the given cluster (or
// all clusters when cluster == "") from the S3-backed report cache. Centralized
// so every CVE-oriented tool reports failures the same way.
func getReportsOrError(cluster string) (*v1alpha1.VulnerabilityReportList, error) {
	reports, err := source.GetVulnerabilityReportList(cluster)
	if err != nil {
		log.Logger.Error("MCP: error getting VulnerabilityReports", "error", err.Error())
		return nil, err
	}
	return reports, nil
}
