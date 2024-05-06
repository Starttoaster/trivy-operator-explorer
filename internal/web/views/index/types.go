package index

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
}
