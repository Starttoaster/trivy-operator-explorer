// Package cve aggregates the per-image vulnerability reports into a cluster-wide,
// per-CVE rollup used by the /cves UI page, the /api/v1/cves endpoint, and the
// MCP tools. Keeping the logic here means all three surfaces rank and filter
// CVEs identically.
package cve

import (
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
)

// AffectedImage describes one image that contains a particular CVE, along with
// the per-image instance of the vulnerability so consumers can correlate
// fixed/installed versions, package class, and per-image ignore state.
type AffectedImage struct {
	Ref               string  `json:"ref"`
	Registry          string  `json:"registry"`
	Repository        string  `json:"repository"`
	Tag               string  `json:"tag"`
	Digest            string  `json:"digest"`
	Cluster           string  `json:"cluster,omitempty"`
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

// Aggregate is the cluster-wide rollup of a single CVE across every image it
// appears in. Severity is taken from the highest-severity occurrence.
type Aggregate struct {
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
	AffectedImages     []AffectedImage `json:"affected_images"`
}

// Pressure is the heuristic ranking used by the "pressure_desc" sort order:
// score (0-10) times the number of affected images. A rough proxy for "how
// worth my time is this CVE today".
func (a *Aggregate) Pressure() float64 {
	return a.MaxScore * float64(a.AffectedImageCount)
}

// Params encodes every filter understood when listing CVEs. All fields are
// optional; the zero value returns every CVE sorted by pressure_desc.
type Params struct {
	Severity    string
	HasFix      *bool
	Class       string
	PackageType string
	CVEID       string
	ShowIgnored bool
	SortBy      string
	Limit       int
}

// Result is the response of List.
type Result struct {
	Total int          `json:"total"`
	CVEs  []*Aggregate `json:"cves"`
}

// List aggregates, filters, sorts, and (optionally) limits the CVEs found in the
// given vulnerability reports.
func List(reports *v1alpha1.VulnerabilityReportList, p Params) Result {
	aggs := build(reports, p.ShowIgnored)

	out := make([]*Aggregate, 0, len(aggs))
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
	return Result{Total: total, CVEs: out}
}

// ListImagesWithCVE returns the single-CVE aggregate for the given CVE ID, or
// found=false when no scanned image contains it.
func ListImagesWithCVE(reports *v1alpha1.VulnerabilityReportList, cveID, severity string, showIgnored bool) (*Aggregate, bool) {
	res := List(reports, Params{
		CVEID:       cveID,
		Severity:    severity,
		ShowIgnored: showIgnored,
		SortBy:      "cve_id_asc",
	})
	if len(res.CVEs) == 0 {
		return nil, false
	}
	return res.CVEs[0], true
}

// build walks every VulnerabilityReport and produces a per-CVE aggregate.
// Ignored CVEs are loaded once per image and applied to each occurrence. When
// showIgnored is false, ignored occurrences are dropped before aggregation, so a
// CVE ignored on every image it appears on will not show up at all.
func build(reports *v1alpha1.VulnerabilityReportList, showIgnored bool) map[string]*Aggregate {
	if reports == nil {
		return map[string]*Aggregate{}
	}

	// Cache ignored CVEs per (registry, repository, tag) so we only hit the
	// database once per image even when the image appears in multiple reports.
	ignoreCache := make(map[string]map[string]db.IgnoredImageVulnerability)
	getIgnored := func(registry, repository, tag string) map[string]db.IgnoredImageVulnerability {
		key := registry + "|" + repository + "|" + tag
		if m, ok := ignoreCache[key]; ok {
			return m
		}
		ignored, err := db.GetIgnoredCVEsForImage(registry, repository, tag)
		if err != nil {
			log.Logger.Error("cve.build: error getting ignored CVEs",
				"registry", registry, "repository", repository, "tag", tag, "error", err.Error())
			ignored = nil
		}
		ignoreCache[key] = ignored
		return ignored
	}

	out := make(map[string]*Aggregate)
	for _, item := range reports.Items {
		registry, repository, tag, digest := utils.NormalizeArtifact(
			item.Report.Registry.Server,
			item.Report.Artifact.Repository,
			item.Report.Artifact.Tag,
			item.Report.Artifact.Digest,
		)
		cluster := item.ObjectMeta.Labels[utils.ClusterLabel]

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

			vClass, vPackageType := utils.DeriveVulnerabilityClassAndPackageType(v)

			agg, ok := out[v.VulnerabilityID]
			if !ok {
				agg = &Aggregate{
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

			agg.AffectedImages = append(agg.AffectedImages, AffectedImage{
				Ref:               utils.AssembleImageRef(registry, repository, tag, digest),
				Registry:          registry,
				Repository:        repository,
				Tag:               tag,
				Digest:            digest,
				Cluster:           cluster,
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

// severityRank maps trivy severity strings to a numeric rank used to pick the
// worst severity across multiple occurrences of the same CVE.
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

// sortAggregates reorders aggs in place. When sortBy is empty or unknown,
// "pressure_desc" is used.
func sortAggregates(aggs []*Aggregate, sortBy string) {
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
			pi := aggs[i].Pressure()
			pj := aggs[j].Pressure()
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
