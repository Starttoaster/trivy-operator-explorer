package index

import (
	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
)

// View contains data for the index page
type View struct {
	// Data for image vulnerabilities
	CriticalVulnerabilities int `json:"critical_vulnerabilities"`
	HighVulnerabilities     int `json:"high_vulnerabilities"`
	MediumVulnerabilities   int `json:"medium_vulnerabilities"`
	LowVulnerabilities      int `json:"low_vulnerabilities"`
	FixAvailableCount       int `json:"fix_available_count"`
	NoFixAvailableCount     int `json:"no_fix_available_count"`
	EOSLCount               int `json:"eosl_count"`
	NoEOSLCount             int `json:"no_eosl_count"`

	// TopImages is the handful of most at-risk images, for the dashboard bar chart.
	TopImages []TopImage `json:"top_images"`

	// Data for compliance reports
	ComplianceReports []complianceview.Data `json:"compliance_reports"`
}

// TopImage is a single image's severity breakdown for the "riskiest images" chart.
type TopImage struct {
	Name     string `json:"name"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}
