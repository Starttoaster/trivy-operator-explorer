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
	Severity string
}

// GetView converts some report data to the /exposedsecret view
// returns view data and "true" if the image was found in the report list
func GetView(data *v1alpha1.ExposedSecretReportList, filters Filters) (View, bool) {
	for _, item := range data.Items {
		itemImageName := getImageNameFromLabels(item.Report.Registry.Server, item.Report.Artifact.Repository, item.Report.Artifact.Tag)
		if filters.Name != itemImageName || filters.Digest != item.Report.Artifact.Digest {
			continue
		}

		i := View{
			Name:   itemImageName,
			Digest: item.Report.Artifact.Digest,
		}

		for _, v := range item.Report.Secrets {
			secret := Secret{
				Severity: string(v.Severity),
				Title:    v.Title,
				Target:   v.Target,
				Match:    v.Match,
			}

			uniqueSecret := i.isUniqueImageSecret(secret.Severity, secret.Title, secret.Target, secret.Match)
			if uniqueSecret {
				// Skip vulnerability if any filters don't match
				// Filter severity
				if filters.Severity != "" && !strings.EqualFold(secret.Severity, filters.Severity) {
					continue
				}

				i.Secrets = append(i.Secrets, secret)
			}
		}

		i = sortView(i)

		return i, true
	}

	return View{}, false
}

func getImageNameFromLabels(registry, repo, tag string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, trim the registry prefix for readability
		// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(repo, "library/"), tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}

func (i View) isUniqueImageSecret(severity, title, target, match string) bool {
	for _, secret := range i.Secrets {
		if severity == secret.Severity && title == secret.Title && target == secret.Target && match == secret.Match {
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
	sort.Slice(v.Secrets, func(j, k int) bool {
		return severityOrder[v.Secrets[j].Severity] > severityOrder[v.Secrets[k].Severity]
	})

	return v
}
