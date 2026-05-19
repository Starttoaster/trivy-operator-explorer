package image

import (
	"sort"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters contains the supported filters for the image view
type Filters struct {
	Name   string
	Digest string

	// optional filters
	Severity    string
	HasFix      bool
	ShowIgnored bool
	Resources   []string
}

// GetView converts some report data to the /image view
// returns view data and "true" if the image was found in the report list
func GetView(data *v1alpha1.VulnerabilityReportList, filters Filters, ignoredCVEs map[string]db.IgnoredImageVulnerability) (View, bool) {
	for _, item := range data.Items {
		// Some trivy-operator reports stuff the full image reference into the
		// Tag field; normalize the artifact spec before we render or key off it.
		registry, repository, tag, digest := utils.NormalizeArtifact(
			item.Report.Registry.Server,
			item.Report.Artifact.Repository,
			item.Report.Artifact.Tag,
			item.Report.Artifact.Digest,
		)

		// If this report is for the image in question, compile its data and return it
		itemImageName := utils.AssembleImageFullName(
			utils.FormatPrettyImageRegistry(registry),
			utils.FormatPrettyImageRepo(repository),
			tag,
			digest,
		)
		if filters.Name != itemImageName || filters.Digest != digest {
			continue
		}

		// Construct image data from this VulnerabilityReport
		i := View{
			Ref: utils.AssembleImageRef(
				registry,
				repository,
				tag,
				digest,
			),
			Registry:   utils.FormatPrettyImageRegistry(registry),
			Repository: utils.FormatPrettyImageRepo(repository),
			Tag:        tag,
			Digest:     digest,
			OSFamily:   string(item.Report.OS.Family),
			OSVersion:  item.Report.OS.Name,
		}
		if item.Report.OS.Eosl {
			i.OSEndOfServiceLife = "true"
		}

		for _, v := range item.Report.Vulnerabilities {
			// Construct this vulnerability's view data
			score := 0.0
			if v.Score != nil {
				score = *v.Score
			}
			// Check if this CVE is ignored
			isIgnored := false
			ignoredReason := ""
			if ignoredCVEs != nil {
				if val, ok := ignoredCVEs[v.VulnerabilityID]; ok {
					isIgnored = true
					ignoredReason = val.Reason
				}
			}

			class, packageType := utils.DeriveVulnerabilityClassAndPackageType(v)
			vuln := Vulnerability{
				ID:                v.VulnerabilityID,
				Severity:          string(v.Severity),
				Score:             score,
				URL:               v.PrimaryLink,
				Resource:          v.Resource,
				Title:             v.Title,
				VulnerableVersion: v.InstalledVersion,
				FixedVersion:      v.FixedVersion,
				Class:             class,
				PackageType:       packageType,
				PkgPath:           v.PkgPath,
				PkgPURL:           v.PkgPURL,
				IsIgnored:         isIgnored,
				IgnoreReason:      ignoredReason,
			}

			// We need to check if the vulnerability is unique
			// Seems rare, but Trivy Operator sometimes gives duplicate CVE data for an image
			uniqueVuln := i.isUniqueVulnerability(vuln.ID)
			if uniqueVuln {
				// Skip vulnerability if it's ignored (unless showIgnored is true)
				if !filters.ShowIgnored && isIgnored {
					continue
				}

				// Skip vulnerability if any filters don't match
				// Filter severity
				if filters.Severity != "" && !strings.EqualFold(vuln.Severity, filters.Severity) {
					continue
				}

				// Filter has-fix
				if filters.HasFix && vuln.FixedVersion == "" {
					continue
				}

				// Filter by resource
				if len(filters.Resources) != 0 && filters.Resources[0] != "" {
					var add bool
					for _, res := range filters.Resources {
						if vuln.Resource == res {
							add = true
						}
					}
					if !add {
						continue
					}
				}

				i.Vulnerabilities = append(i.Vulnerabilities, vuln)
			}
		}

		i = sortView(i)

		return i, true
	}

	return View{}, false
}

func (i View) isUniqueVulnerability(cveID string) bool {
	for _, vuln := range i.Vulnerabilities {
		if cveID == vuln.ID {
			return false
		}
	}

	return true
}

func sortView(v View) View {
	// Create an order for severities to sort by
	// Define custom priority order
	severityOrder := map[string]int{
		"CRITICAL": 3,
		"HIGH":     2,
		"MEDIUM":   1,
		"LOW":      0,
	}

	// Sort the slice by severity in descending order
	sort.Slice(v.Vulnerabilities, func(j, k int) bool {
		if v.Vulnerabilities[j].Severity != v.Vulnerabilities[k].Severity {
			return severityOrder[v.Vulnerabilities[j].Severity] > severityOrder[v.Vulnerabilities[k].Severity]
		}

		return v.Vulnerabilities[j].Score > v.Vulnerabilities[k].Score
	})

	return v
}
