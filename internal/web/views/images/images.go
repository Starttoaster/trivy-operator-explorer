package images

import (
	"fmt"
	"sort"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/kube"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters represents the available optional filters to the images view
type Filters struct {
	HasFix bool
}

// GetView converts some report data to the /images view
func GetView(data *v1alpha1.VulnerabilityReportList, allClusterImagesMap map[string]kube.ContainerImage, filters Filters) View {
	var iMap = make(map[string]Data)

	for _, item := range data.Items {
		// Determine if this image is already in the map
		// We add its resources to the current item in the map if it already exists
		iMapKey := getNiceImageFullName(getImageRegistry(item.Report.Registry.Server), getImageName(item.Report.Artifact.Repository), item.Report.Artifact.Tag)
		_, ok := iMap[iMapKey]
		if ok {
			resourceData := ResourceMetadata{
				Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
				Name:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
				Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
			}
			iMap[iMapKey].Resources[resourceData] = struct{}{}
			continue
		}

		// If we make it here, the image wasn't in the map yet
		// Process all image metadata
		image := Data{
			Registry:  getImageRegistry(item.Report.Registry.Server),
			Name:      getImageName(item.Report.Artifact.Repository),
			Tag:       item.Report.Artifact.Tag,
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

		// Process all vulnerabilities from this vulnerability report
		vMap := make(map[string]Vulnerability)
		for _, v := range item.Report.Vulnerabilities {
			vMapKey := v.VulnerabilityID
			_, ok := vMap[vMapKey]
			if ok {
				// Skip if we've already processed this vulnerability
				continue
			}

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

			// Fixed version counter for index page
			if vuln.FixedVersion == "" {
				image.NoFixAvailableCount++
			} else {
				image.FixAvailableCount++
			}

			vMap[vMapKey] = vuln
		}

		// Add vulnerability map data to image data
		for _, vuln := range vMap {
			image.addVulnerabilityData(vuln)
		}

		// Add image to image map
		iMap[iMapKey] = image
	}

	// Add unscanned image data to the image map using the total list of cluster images
	// We don't use the image digest to determine uniqueness because for some reason trivy-operator and kubernetes
	// sometimes disagree on the image's digest
	for k, v := range allClusterImagesMap {
		if _, ok := iMap[k]; !ok {
			resourceData := make(map[ResourceMetadata]struct{})
			for resource := range v.Resources {
				r := ResourceMetadata{
					Kind:      resource.Kind,
					Name:      resource.Name,
					Namespace: resource.Namespace,
				}
				resourceData[r] = struct{}{}
			}
			iMap[k] = Data{
				Name: k,
				// Hack: digest is used by the /images page for the dropdown button's id
				// Should be a safe assumption that an unscanned image is unique by registry/name:tag instead of digest, so just using this here
				Digest:    k,
				Resources: resourceData,
				Unscanned: true,
			}
		}
	}

	var i View
	for _, v := range iMap {
		i = append(i, v)
	}

	i = sortView(i)

	return i
}

func sortView(i View) View {
	// Sort the slice by severity in descending order, with unscanned items at the bottom
	sort.Slice(i, func(j, k int) bool {
		// If one is unscanned and the other isn't, unscanned goes to bottom
		if i[j].Unscanned != i[k].Unscanned {
			return !i[j].Unscanned // unscanned items (true) go to bottom
		}

		// If both are unscanned, sort alphabetically by name
		if i[j].Unscanned && i[k].Unscanned {
			return i[j].Name < i[k].Name
		}

		// For scanned items, sort by vulnerability severity in descending order
		if len(i[j].CriticalVulnerabilities) != len(i[k].CriticalVulnerabilities) {
			return len(i[j].CriticalVulnerabilities) > len(i[k].CriticalVulnerabilities)
		}

		if len(i[j].HighVulnerabilities) != len(i[k].HighVulnerabilities) {
			return len(i[j].HighVulnerabilities) > len(i[k].HighVulnerabilities)
		}

		if len(i[j].MediumVulnerabilities) != len(i[k].MediumVulnerabilities) {
			return len(i[j].MediumVulnerabilities) > len(i[k].MediumVulnerabilities)
		}

		if len(i[j].LowVulnerabilities) != len(i[k].LowVulnerabilities) {
			return len(i[j].LowVulnerabilities) > len(i[k].LowVulnerabilities)
		}

		// If all vulnerability counts are equal, sort alphabetically by name
		return i[j].Name < i[k].Name
	})

	return i
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

func getImageRegistry(registry string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, it's more common to see this without the index.docker.io registry, so we just strip it here
		return ""
	}
	return registry
}

// getImageName trims the prefix on docker hub images
func getImageName(repo string) string {
	return strings.TrimPrefix(repo, "library/")
}

func getNiceImageFullName(registry, repo, tag string) string {
	if registry == "" {
		return fmt.Sprintf("%s:%s", repo, tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}
