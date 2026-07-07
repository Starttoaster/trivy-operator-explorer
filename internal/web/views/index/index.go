package index

import (
	"sort"

	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
)

// topImagesLimit is how many images the dashboard "riskiest images" chart shows.
const topImagesLimit = 10

// GetView converts some report data to the / view
func GetView(vulnList imagesview.View, complianceList complianceview.View) View {
	var i View

	var ranked []TopImage

	// Process image vulnerability data
	for _, image := range vulnList {
		i.CriticalVulnerabilities += len(image.CriticalVulnerabilities)
		i.HighVulnerabilities += len(image.HighVulnerabilities)
		i.MediumVulnerabilities += len(image.MediumVulnerabilities)
		i.LowVulnerabilities += len(image.LowVulnerabilities)

		i.FixAvailableCount += image.FixAvailableCount
		i.NoFixAvailableCount += image.NoFixAvailableCount

		if image.OSEndOfServiceLife != "" {
			i.EOSLCount++
		} else {
			i.NoEOSLCount++
		}

		name := image.Name
		if image.Tag != "" {
			name += ":" + image.Tag
		}
		ti := TopImage{
			Name:     name,
			Critical: len(image.CriticalVulnerabilities),
			High:     len(image.HighVulnerabilities),
			Medium:   len(image.MediumVulnerabilities),
			Low:      len(image.LowVulnerabilities),
		}
		if ti.Critical+ti.High+ti.Medium+ti.Low > 0 {
			ranked = append(ranked, ti)
		}
	}

	// Rank images by a severity-weighted score and keep the top N.
	sort.SliceStable(ranked, func(a, b int) bool {
		return riskScore(ranked[a]) > riskScore(ranked[b])
	})
	if len(ranked) > topImagesLimit {
		ranked = ranked[:topImagesLimit]
	}
	i.TopImages = ranked

	// Process compliance data
	i.ComplianceReports = complianceList

	return i
}

// riskScore is a severity-weighted heuristic used only to order the dashboard
// "riskiest images" chart.
func riskScore(t TopImage) int {
	return t.Critical*1000 + t.High*100 + t.Medium*10 + t.Low
}
