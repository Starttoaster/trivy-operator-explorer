package images

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters represents the available optional filters to the images view
type Filters struct {
	HasFix bool
}

// GetView converts some report data to the /images view
func GetView(data *v1alpha1.VulnerabilityReportList, filters Filters) View {
	var i View

	for _, item := range data.Items {
		// Construct image data from this VulnerabilityReport
		image := Data{
			Name:      getImageNameFromLabels(item.Report.Registry.Server, item.Report.Artifact.Repository, item.Report.Artifact.Tag),
			Digest:    item.Report.Artifact.Digest,
			OSFamily:  string(item.Report.OS.Family),
			OSVersion: item.Report.OS.Name,
		}
		if item.Report.OS.Eosl {
			image.OSEndOfServiceLife = "true"
		}
		resourceData := ResourceMetadata{
			Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
			Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
		}
		image.Resources = make(map[ResourceMetadata]struct{})
		image.Resources[resourceData] = struct{}{}

		// Check if the image used is unique, by fullname (registry/repository:tag) and digest
		// This check is a little inefficient because it loops through the whole image list
		// I was previously using maps for uniqueness and then converted over to slices because they're easier to sort server-side
		imageIndex, uniqueImage := i.isUniqueImage(image.Name, image.Digest)

		// Add image if unique, retrieving the new image's data index in the slice
		if uniqueImage {
			i = append(i, image)
			imageIndex = len(i) - 1
		} else {
			// Add this resource to the image at the given index if image data already present
			i[imageIndex].Resources[resourceData] = struct{}{}
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

			// Filter by hasfix
			if filters.HasFix {
				if strings.TrimSpace(vuln.FixedVersion) == "" {
					continue
				}
			}

			// If the image is not unique, we need to check if the vulnerability is unique too
			// Seems rare, but Trivy Operator sometimes gives duplicate CVE data for an image
			uniqueVuln := i[imageIndex].isUniqueImageVulnerability(vuln.ID, vuln.Severity)
			if uniqueVuln {
				i[imageIndex].addVulnerabilityData(vuln)
			}
		}
	}

	i = sortView(i)

	return i
}

func sortView(i View) View {
	// Sort the slice by severity in descending order
	sort.Slice(i, func(j, k int) bool {
		if len(i[j].CriticalVulnerabilities) != len(i[k].CriticalVulnerabilities) {
			return len(i[j].CriticalVulnerabilities) > len(i[k].CriticalVulnerabilities)
		}

		if len(i[j].HighVulnerabilities) != len(i[k].HighVulnerabilities) {
			return len(i[j].HighVulnerabilities) > len(i[k].HighVulnerabilities)
		}

		if len(i[j].MediumVulnerabilities) != len(i[k].MediumVulnerabilities) {
			return len(i[j].MediumVulnerabilities) > len(i[k].MediumVulnerabilities)
		}

		return len(i[j].LowVulnerabilities) > len(i[k].LowVulnerabilities)
	})

	return i
}

func (i View) isUniqueImage(name, digest string) (int, bool) {
	for index, image := range i {
		if name == image.Name && digest == image.Digest {
			return index, false
		}
	}

	return 0, true
}

func (i Data) isUniqueImageVulnerability(cveID, severity string) bool {
	switch strings.ToLower(severity) {
	case "critical":
		for _, vuln := range i.CriticalVulnerabilities {
			if cveID == vuln.ID {
				return false
			}
		}
	case "high":
		for _, vuln := range i.HighVulnerabilities {
			if cveID == vuln.ID {
				return false
			}
		}
	case "medium":
		for _, vuln := range i.MediumVulnerabilities {
			if cveID == vuln.ID {
				return false
			}
		}
	case "low":
		for _, vuln := range i.LowVulnerabilities {
			if cveID == vuln.ID {
				return false
			}
		}
	}

	return true
}

func (i *Data) addVulnerabilityData(v Vulnerability) {
	switch strings.ToLower(v.Severity) {
	case "critical":
		i.CriticalVulnerabilities = append(i.CriticalVulnerabilities, v)
	case "high":
		i.HighVulnerabilities = append(i.HighVulnerabilities, v)
	case "medium":
		i.MediumVulnerabilities = append(i.MediumVulnerabilities, v)
	case "low":
		i.LowVulnerabilities = append(i.LowVulnerabilities, v)
	}

}

func getImageNameFromLabels(registry, repo, tag string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, trim the registry prefix for readability
		// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(repo, "library/"), tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}
