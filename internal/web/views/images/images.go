package images

import (
	"sort"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters represents the available optional filters to the images view
type Filters struct {
	HasFix      bool
	ShowIgnored bool

	// Image-level filters applied as a post-aggregation pass after vulnerabilities
	// have been collected. Empty / nil values match anything.

	// Severity, when non-empty, restricts results to images that contain at
	// least one non-ignored vulnerability of the given severity. Comparison is
	// case-insensitive (e.g. "critical" matches "CRITICAL").
	Severity string

	// OSFamily, when non-empty, restricts results to images whose detected
	// OS family matches (case-insensitive, exact match).
	OSFamily string

	// EOSL is tri-state: nil means "no filter". true keeps only images whose
	// OS is end-of-service-life; false keeps only images whose OS is not EOSL.
	// Unscanned images have no OS metadata and are excluded by any non-nil EOSL.
	EOSL *bool

	// CVEIDs, when non-empty, restricts results to images that contain *all*
	// of the listed CVE IDs (logical AND). Ignored CVEs only count when
	// ShowIgnored is true (matching the existing per-image behavior).
	CVEIDs []string

	// Class, when non-empty, restricts results to images that contain at least
	// one vulnerability of the given Trivy package class (e.g. "os-pkgs" or
	// "lang-pkgs"). Case-insensitive.
	Class string
}

// GetView converts some report data to the /images view
func GetView(data *v1alpha1.VulnerabilityReportList, allClusterImagesMap map[string]kube.ContainerImage, filters Filters) View {
	var iMap = make(map[string]Data)

	for _, item := range data.Items {
		// Some trivy-operator reports stuff the full image reference into the
		// Tag field; normalize the artifact spec before we render or key off it.
		registry, repository, tag, digest := utils.NormalizeArtifact(
			item.Report.Registry.Server,
			item.Report.Artifact.Repository,
			item.Report.Artifact.Tag,
			item.Report.Artifact.Digest,
		)

		// Determine if this image is already in the map
		// We add its resources to the current item in the map if it already exists
		iMapKey := utils.AssembleImageFullName(
			utils.FormatPrettyImageRegistry(registry),
			utils.FormatPrettyImageRepo(repository),
			tag,
			digest,
		)
		cluster := item.ObjectMeta.Labels[utils.ClusterLabel]

		_, ok := iMap[iMapKey]
		if ok {
			resourceData := ResourceMetadata{
				Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
				Name:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
				Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
			}
			iMap[iMapKey].Resources[resourceData] = struct{}{}
			if cluster != "" {
				iMap[iMapKey].Clusters[cluster] = struct{}{}
			}
			continue
		}

		// If we make it here, the image wasn't in the map yet
		// Process all image metadata
		image := Data{
			Ref: utils.AssembleImageRef(
				registry,
				repository,
				tag,
				digest,
			),
			Registry:  utils.FormatPrettyImageRegistry(registry),
			Name:      utils.FormatPrettyImageRepo(repository),
			Tag:       tag,
			Digest:    digest,
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
		image.Clusters = make(map[string]struct{})
		if cluster != "" {
			image.Clusters[cluster] = struct{}{}
		}

		// Get ignored CVEs from database (if 'show ignored' filter is false)
		var ignoredCVEs map[string]db.IgnoredImageVulnerability
		if !filters.ShowIgnored {
			var err error
			ignoredCVEs, err = db.GetIgnoredCVEsForImage(registry, image.Name, image.Tag)
			if err != nil {
				log.Logger.Error("error getting ignored CVEs", "error", err.Error())
				// Continue without ignored CVEs rather than failing the request
				ignoredCVEs = nil
			}
		}

		// Process all vulnerabilities from this vulnerability report
		vMap := make(map[string]Vulnerability)
		for _, v := range item.Report.Vulnerabilities {
			vMapKey := v.VulnerabilityID
			_, ok := vMap[vMapKey]
			if ok {
				// Skip if we've already processed this vulnerability
				continue
			}

			// Check if this CVE is ignored (if 'show ignored' filter is false)
			if !filters.ShowIgnored {
				if ignoredCVEs != nil {
					if _, isIgnored := ignoredCVEs[v.VulnerabilityID]; isIgnored {
						continue
					}
				}
			}

			// Construct this vulnerability's view data
			score := 0.0
			if v.Score != nil {
				score = *v.Score
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
		iMapKey := utils.AssembleImageFullName(
			"",
			v.Name,
			v.Tag,
			v.Digest,
		)
		if _, ok := iMap[iMapKey]; !ok {
			resourceData := make(map[ResourceMetadata]struct{})
			for resource := range v.Resources {
				r := ResourceMetadata{
					Kind:      resource.Kind,
					Name:      resource.Name,
					Namespace: resource.Namespace,
				}
				resourceData[r] = struct{}{}
			}
			clusterData := make(map[string]struct{}, len(v.Clusters))
			for c := range v.Clusters {
				clusterData[c] = struct{}{}
			}
			iMap[k] = Data{
				Ref:       utils.AssembleImageRef("", v.Name, v.Tag, v.Digest),
				Name:      v.Name,
				Tag:       v.Tag,
				Digest:    v.Digest,
				Resources: resourceData,
				Clusters:  clusterData,
				Unscanned: true,
			}
		}
	}

	var i View
	for _, v := range iMap {
		if !matchesImageLevelFilters(v, filters) {
			continue
		}
		i = append(i, v)
	}

	i = sortView(i)

	return i
}

// matchesImageLevelFilters returns true if the image satisfies the image-level
// filters (Severity, OSFamily, EOSL, CVEIDs). It is the post-aggregation pass
// referenced in Filters' documentation.
func matchesImageLevelFilters(d Data, f Filters) bool {
	if f.Severity != "" {
		hasMatch := false
		switch strings.ToLower(f.Severity) {
		case "critical":
			hasMatch = len(d.CriticalVulnerabilities) > 0
		case "high":
			hasMatch = len(d.HighVulnerabilities) > 0
		case "medium":
			hasMatch = len(d.MediumVulnerabilities) > 0
		case "low":
			hasMatch = len(d.LowVulnerabilities) > 0
		}
		if !hasMatch {
			return false
		}
	}

	if f.OSFamily != "" {
		if !strings.EqualFold(d.OSFamily, f.OSFamily) {
			return false
		}
	}

	if f.EOSL != nil {
		isEOSL := d.OSEndOfServiceLife == "true"
		if isEOSL != *f.EOSL {
			return false
		}
	}

	if len(f.CVEIDs) > 0 {
		present := make(map[string]struct{})
		for _, v := range d.CriticalVulnerabilities {
			present[v.ID] = struct{}{}
		}
		for _, v := range d.HighVulnerabilities {
			present[v.ID] = struct{}{}
		}
		for _, v := range d.MediumVulnerabilities {
			present[v.ID] = struct{}{}
		}
		for _, v := range d.LowVulnerabilities {
			present[v.ID] = struct{}{}
		}
		for _, want := range f.CVEIDs {
			if want == "" {
				continue
			}
			if _, ok := present[want]; !ok {
				return false
			}
		}
	}

	if f.Class != "" {
		hasClass := false
		for _, group := range [][]Vulnerability{
			d.CriticalVulnerabilities, d.HighVulnerabilities, d.MediumVulnerabilities, d.LowVulnerabilities,
		} {
			for _, v := range group {
				if strings.EqualFold(v.Class, f.Class) {
					hasClass = true
					break
				}
			}
			if hasClass {
				break
			}
		}
		if !hasClass {
			return false
		}
	}

	return true
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
