package compliance

// View a list of data about cluster compliance reports
type View []Data

// Data contains compliance report data
type Data struct {
	ID      string
	Title   string
	Summary Summary
	Checks  []Check
}

// Summary contains the summary fail/pass count for a compliance report
type Summary struct {
	FailCount int
	PassCount int

	CriticalFailCount int
	HighFailCount     int
	MediumFailCount   int
	LowFailCount      int
	UnknownFailCount  int
}

// Check data related to a compliance report check
type Check struct {
	IDNumber    string
	ID          []CheckID
	Name        string
	Description string
	Severity    string
	TotalFailed *int
}

// CheckID represents an ID/URL pair of data for a check
type CheckID struct {
	ID  string
	URL string
}
