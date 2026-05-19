package mcp

import (
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
)

// affectedImage describes one image that contains a particular CVE, along
// with the per-image instance of the vulnerability so LLMs can correlate
// fixed/installed versions, package class, and per-image ignore state.
type affectedImage struct {
	Ref               string  `json:"ref"`
	Registry          string  `json:"registry"`
	Repository        string  `json:"repository"`
	Tag               string  `json:"tag"`
	Digest            string  `json:"digest"`
	VulnerableVersion string  `json:"vulnerable_version,omitempty"`
	FixedVersion      string  `json:"fixed_version,omitempty"`
	Resource          string  `json:"resource,omitempty"`
	Class             string  `json:"class,omitempty"`
	PackageType       string  `json:"package_type,omitempty"`
	PkgPath           string  `json:"pkg_path,omitempty"`
	PkgPURL           string  `json:"pkg_purl,omitempty"`
	Score             float64 `json:"score,omitempty"`
	IsIgnored         bool    `json:"is_ignored"`
	IgnoreReason      string  `json:"ignore_reason,omitempty"`
}

// cveAggregate is the cluster-wide rollup of a single CVE across every image
// it appears in. Severity is taken from the highest-severity occurrence (in
// practice trivy reports the same severity for a CVE on every image, but we
// defensively pick the worst).
type cveAggregate struct {
	CVEID              string          `json:"cve_id"`
	Severity           string          `json:"severity"`
	MaxScore           float64         `json:"max_score"`
	Title              string          `json:"title,omitempty"`
	URL                string          `json:"url,omitempty"`
	HasFix             bool            `json:"has_fix"`
	Class              string          `json:"class,omitempty"`
	PackageType        string          `json:"package_type,omitempty"`
	AffectedImageCount int             `json:"affected_image_count"`
	IgnoredOnAllImages bool            `json:"ignored_on_all_images"`
	AffectedImages     []affectedImage `json:"affected_images"`
}

// cvePressure is the heuristic ranking used by the pressure_desc sort order
// in list_cves: score (0-10) times the number of affected images. It is a
// rough proxy for "how worth my time is this CVE today".
func (c *cveAggregate) cvePressure() float64 {
	return c.MaxScore * float64(c.AffectedImageCount)
}

// aggregateCVEs walks every VulnerabilityReport in the cluster and produces a
// per-CVE aggregate. Ignored CVEs are loaded once per image and applied to
// each occurrence so list_cves and list_images_with_cve get consistent
// is_ignored / ignore_reason metadata.
//
// The optional showIgnored flag controls whether occurrences that are
// ignored in the DB are included in the aggregate. When false (the default),
// ignored occurrences are dropped *before* aggregation, so a CVE that is
// ignored on every image it appears on will not show up at all.
func aggregateCVEs(reports *v1alpha1.VulnerabilityReportList, showIgnored bool) map[string]*cveAggregate {
	if reports == nil {
		return map[string]*cveAggregate{}
	}

	// Cache ignored CVEs per (registry, repository, tag) so we only hit the
	// database once per image even when the same image appears in multiple
	// reports (different workloads).
	ignoreCache := make(map[string]map[string]db.IgnoredImageVulnerability)
	getIgnored := func(registry, repository, tag string) map[string]db.IgnoredImageVulnerability {
		key := registry + "|" + repository + "|" + tag
		if m, ok := ignoreCache[key]; ok {
			return m
		}
		ignored, err := db.GetIgnoredCVEsForImage(registry, repository, tag)
		if err != nil {
			log.Logger.Error("aggregateCVEs: error getting ignored CVEs",
				"registry", registry, "repository", repository, "tag", tag,
				"error", err.Error())
			ignored = nil
		}
		ignoreCache[key] = ignored
		return ignored
	}

	out := make(map[string]*cveAggregate)
	for _, item := range reports.Items {
		// Some trivy-operator reports stuff the full image reference into the
		// Tag field; normalize the artifact spec before we render or key off it.
		registry, repository, tag, digest := utils.NormalizeArtifact(
			item.Report.Registry.Server,
			item.Report.Artifact.Repository,
			item.Report.Artifact.Tag,
			item.Report.Artifact.Digest,
		)

		// Track which (image, CVE) pairs we've already counted so duplicate
		// vulnerability rows on the same report don't double-count.
		seenOnImage := make(map[string]struct{})

		ignored := getIgnored(registry, repository, tag)
		for _, v := range item.Report.Vulnerabilities {
			if _, dup := seenOnImage[v.VulnerabilityID]; dup {
				continue
			}
			seenOnImage[v.VulnerabilityID] = struct{}{}

			isIgnored := false
			ignoreReason := ""
			if ignored != nil {
				if row, ok := ignored[v.VulnerabilityID]; ok {
					isIgnored = true
					ignoreReason = row.Reason
				}
			}
			if isIgnored && !showIgnored {
				continue
			}

			score := 0.0
			if v.Score != nil {
				score = *v.Score
			}

			// Resolve class/package_type once per occurrence, falling back to
			// the packagePURL ("pkg:<type>/...") when trivy left the explicit
			// fields blank. Both the top-level aggregate and the affected_images
			// entry below need to see the derived values so MCP clients can
			// filter list_cves?class=os-pkgs without re-parsing purls.
			vClass, vPackageType := utils.DeriveVulnerabilityClassAndPackageType(v)

			agg, ok := out[v.VulnerabilityID]
			if !ok {
				agg = &cveAggregate{
					CVEID:              v.VulnerabilityID,
					Severity:           string(v.Severity),
					MaxScore:           score,
					Title:              v.Title,
					URL:                v.PrimaryLink,
					HasFix:             strings.TrimSpace(v.FixedVersion) != "",
					Class:              vClass,
					PackageType:        vPackageType,
					IgnoredOnAllImages: true,
				}
				out[v.VulnerabilityID] = agg
			} else {
				if severityRank(string(v.Severity)) > severityRank(agg.Severity) {
					agg.Severity = string(v.Severity)
				}
				if score > agg.MaxScore {
					agg.MaxScore = score
				}
				if strings.TrimSpace(v.FixedVersion) != "" {
					agg.HasFix = true
				}
				if agg.Class == "" {
					agg.Class = vClass
				}
				if agg.PackageType == "" {
					agg.PackageType = vPackageType
				}
				if agg.Title == "" {
					agg.Title = v.Title
				}
				if agg.URL == "" {
					agg.URL = v.PrimaryLink
				}
			}

			if !isIgnored {
				agg.IgnoredOnAllImages = false
			}

			agg.AffectedImages = append(agg.AffectedImages, affectedImage{
				Ref:               utils.AssembleImageRef(registry, repository, tag, digest),
				Registry:          registry,
				Repository:        repository,
				Tag:               tag,
				Digest:            digest,
				VulnerableVersion: v.InstalledVersion,
				FixedVersion:      v.FixedVersion,
				Resource:          v.Resource,
				Class:             vClass,
				PackageType:       vPackageType,
				PkgPath:           v.PkgPath,
				PkgPURL:           v.PkgPURL,
				Score:             score,
				IsIgnored:         isIgnored,
				IgnoreReason:      ignoreReason,
			})
			agg.AffectedImageCount = len(agg.AffectedImages)
		}
	}

	return out
}

// severityRank maps trivy severity strings to a numeric rank used to pick
// the worst severity across multiple report occurrences of the same CVE.
// Unknown values are ranked 0, so a known severity always beats unknown.
func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// listCVEsParams encodes every filter understood by the list_cves MCP tool.
// All fields are optional; the zero value returns every CVE in the cluster
// sorted by pressure_desc.
type listCVEsParams struct {
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
type listCVEsResult struct {
	Total int             `json:"total"`
	CVEs  []*cveAggregate `json:"cves"`
}

// runListCVEs is the shared implementation behind the list_cves MCP tool. It
// is broken out from the tool wrapper so it can be unit-tested with a
// canned report list.
func runListCVEs(reports *v1alpha1.VulnerabilityReportList, p listCVEsParams) listCVEsResult {
	aggs := aggregateCVEs(reports, p.ShowIgnored)

	out := make([]*cveAggregate, 0, len(aggs))
	for _, a := range aggs {
		if p.Severity != "" && !strings.EqualFold(a.Severity, p.Severity) {
			continue
		}
		if p.Class != "" && !strings.EqualFold(a.Class, p.Class) {
			continue
		}
		if p.PackageType != "" && !strings.EqualFold(a.PackageType, p.PackageType) {
			continue
		}
		if p.CVEID != "" && !strings.EqualFold(a.CVEID, p.CVEID) {
			continue
		}
		if p.HasFix != nil && a.HasFix != *p.HasFix {
			continue
		}
		out = append(out, a)
	}

	sortAggregates(out, p.SortBy)

	total := len(out)
	if p.Limit > 0 && len(out) > p.Limit {
		out = out[:p.Limit]
	}
	return listCVEsResult{Total: total, CVEs: out}
}

// sortAggregates reorders aggs in place using the requested ordering. When
// sortBy is empty or unknown, "pressure_desc" is used.
func sortAggregates(aggs []*cveAggregate, sortBy string) {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "score_desc":
		sort.SliceStable(aggs, func(i, j int) bool {
			if aggs[i].MaxScore != aggs[j].MaxScore {
				return aggs[i].MaxScore > aggs[j].MaxScore
			}
			return aggs[i].CVEID < aggs[j].CVEID
		})
	case "affected_count_desc":
		sort.SliceStable(aggs, func(i, j int) bool {
			if aggs[i].AffectedImageCount != aggs[j].AffectedImageCount {
				return aggs[i].AffectedImageCount > aggs[j].AffectedImageCount
			}
			return aggs[i].CVEID < aggs[j].CVEID
		})
	case "cve_id_asc":
		sort.SliceStable(aggs, func(i, j int) bool {
			return aggs[i].CVEID < aggs[j].CVEID
		})
	default: // pressure_desc
		sort.SliceStable(aggs, func(i, j int) bool {
			pi := aggs[i].cvePressure()
			pj := aggs[j].cvePressure()
			if pi != pj {
				return pi > pj
			}
			if severityRank(aggs[i].Severity) != severityRank(aggs[j].Severity) {
				return severityRank(aggs[i].Severity) > severityRank(aggs[j].Severity)
			}
			return aggs[i].CVEID < aggs[j].CVEID
		})
	}
}

// listImagesWithCVEParams encodes the inputs to the list_images_with_cve
// MCP tool. CVEID is required; Severity is an optional defensive filter.
type listImagesWithCVEParams struct {
	CVEID       string `json:"cve_id" jsonschema:"required CVE ID to look up (e.g. 'CVE-2023-1234'), case-insensitive"`
	Severity    string `json:"severity,omitempty" jsonschema:"optional severity filter (critical|high|medium|low), case-insensitive"`
	ShowIgnored bool   `json:"show_ignored,omitempty" jsonschema:"when true include occurrences that are marked as ignored in the database"`
}

// listImagesWithCVEResult is the typed response for list_images_with_cve.
type listImagesWithCVEResult struct {
	CVE   *cveAggregate `json:"cve,omitempty"`
	Found bool          `json:"found"`
}

func runListImagesWithCVE(reports *v1alpha1.VulnerabilityReportList, p listImagesWithCVEParams) listImagesWithCVEResult {
	res := runListCVEs(reports, listCVEsParams{
		CVEID:       p.CVEID,
		Severity:    p.Severity,
		ShowIgnored: p.ShowIgnored,
		SortBy:      "cve_id_asc",
	})
	if len(res.CVEs) == 0 {
		return listImagesWithCVEResult{Found: false}
	}
	return listImagesWithCVEResult{Found: true, CVE: res.CVEs[0]}
}

// getReportsOrError loads the vulnerability reports from the kube client and
// returns them, along with a fallback empty result wrapper when the call
// fails. Centralized so every CVE-oriented tool reports failures the same way.
func getReportsOrError() (*v1alpha1.VulnerabilityReportList, error) {
	reports, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("MCP: error getting VulnerabilityReports", "error", err.Error())
		return nil, err
	}
	return reports, nil
}
