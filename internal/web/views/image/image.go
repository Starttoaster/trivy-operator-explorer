package image

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters contains the supported filters for the image view
type Filters struct {
	Name   string
	Digest string

	// optional filters
	Severity  string
	HasFix    bool
	Resources []string
}

// GetView converts some report data to the /image view
// returns view data and "true" if the image was found in the report list
func GetView(data *v1alpha1.VulnerabilityReportList, filters Filters) (View, bool) {
	for _, item := range data.Items {
		// If this report is for the image in question, compile its data and return it
		itemImageName := getImageNameFromLabels(item.Report.Registry.Server, item.Report.Artifact.Repository, item.Report.Artifact.Tag)
		if filters.Name != itemImageName || filters.Digest != item.Report.Artifact.Digest {
			continue
		}

		// Construct image data from this VulnerabilityReport
		i := View{
			Name:      itemImageName,
			Digest:    item.Report.Artifact.Digest,
			OSFamily:  string(item.Report.OS.Family),
			OSVersion: item.Report.OS.Name,
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
			vuln := Vulnerability{
				ID:                v.VulnerabilityID,
				Severity:          string(v.Severity),
				Score:             score,
				URL:               v.PrimaryLink,
				Resource:          v.Resource,
				Title:             v.Title,
				VulnerableVersion: v.InstalledVersion,
				FixedVersion:      v.FixedVersion,
			}

			// We need to check if the vulnerability is unique
			// Seems rare, but Trivy Operator sometimes gives duplicate CVE data for an image
			uniqueVuln := i.isUniqueVulnerability(vuln.ID)
			if uniqueVuln {
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

func getImageNameFromLabels(registry, repo, tag string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, trim the registry prefix for readability
		// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(repo, "library/"), tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
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
