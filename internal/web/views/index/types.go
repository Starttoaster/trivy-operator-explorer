package index

import (
	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
)

// VulnerabilityCountPoint is one day's snapshot for the vulnerabilities-over-time chart.
type VulnerabilityCountPoint struct {
	Date     string
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// View contains data for the index page
type View struct {
	// Data for image vulnerabilities
	CriticalVulnerabilities int
	HighVulnerabilities     int
	MediumVulnerabilities   int
	LowVulnerabilities      int
	FixAvailableCount       int
	NoFixAvailableCount     int
	EOSLCount               int
	NoEOSLCount             int

	// Full history of daily vulnerability counts (for chart)
	VulnerabilityCountHistory []VulnerabilityCountPoint

	// Data for compliance reports
	ComplianceReports []complianceview.Data
}
