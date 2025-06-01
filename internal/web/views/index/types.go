package index

import (
	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
)

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

	// Data for compliance reports
	ComplianceReports []complianceview.Data
}
