package index

import (
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
)

// GetView converts some report data to the / view
func GetView(vulnList imagesview.View) View {
	var i View

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
	}

	return i
}
