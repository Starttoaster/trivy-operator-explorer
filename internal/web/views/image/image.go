package views

import (
	"sort"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// SortImageVulnerabilityView sorts the provided ImageVulnerabilityView's data slice
func SortImageVulnerabilityView(v ImageVulnerabilityView) ImageVulnerabilityView {
	// Sort by vulnerability severity separately
	// Because sometimes low or other tier vulnerabilities also have high scores
	var (
		crit []ImageVulnerabilityData
		high []ImageVulnerabilityData
		med  []ImageVulnerabilityData
		low  []ImageVulnerabilityData
	)
	for _, data := range v.Data {
		switch data.Severity {
		case string(v1alpha1.SeverityCritical):
			crit = append(crit, data)
		case string(v1alpha1.SeverityHigh):
			high = append(high, data)
		case string(v1alpha1.SeverityMedium):
			med = append(med, data)
		case string(v1alpha1.SeverityLow):
			low = append(low, data)
		}
	}

	// Sort each severity tier by score separately
	sort.SliceStable(crit, func(i, j int) bool {
		return crit[i].Score > crit[j].Score
	})
	sort.SliceStable(high, func(i, j int) bool {
		return high[i].Score > high[j].Score
	})
	sort.SliceStable(med, func(i, j int) bool {
		return med[i].Score > med[j].Score
	})
	sort.SliceStable(low, func(i, j int) bool {
		return low[i].Score > low[j].Score
	})

	// Combine now to one mega slice
	var data []ImageVulnerabilityData
	data = append(data, crit...)
	data = append(data, high...)
	data = append(data, med...)
	data = append(data, low...)
	v.Data = data
	return v
}
