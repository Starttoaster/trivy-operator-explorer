package compliance

// View a list of data about cluster compliance reports
type View []Data

// Data contains compliance report data
type Data struct {
	Cluster string  `json:"cluster"`
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Summary Summary `json:"summary"`
	Checks  []Check `json:"checks"`
}

// Summary contains the summary fail/pass count for a compliance report
type Summary struct {
	FailCount int `json:"fail_count"`
	PassCount int `json:"pass_count"`

	CriticalFailCount int `json:"critical_fail_count"`
	HighFailCount     int `json:"high_fail_count"`
	MediumFailCount   int `json:"medium_fail_count"`
	LowFailCount      int `json:"low_fail_count"`
	UnknownFailCount  int `json:"unknown_fail_count"`
}

// Check data related to a compliance report check
type Check struct {
	IDNumber    string    `json:"id_number"`
	ID          []CheckID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	TotalFailed *int      `json:"total_failed,omitempty"`
}

// CheckID represents an ID/URL pair of data for a check
type CheckID struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}
