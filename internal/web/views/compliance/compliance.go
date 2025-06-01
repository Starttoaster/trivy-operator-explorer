package compliance

import (
	"fmt"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"strings"
)

// GetView converts some report data to the /compliancereports view
func GetView(data *v1alpha1.ClusterComplianceReportList) View {
	var r View

	for _, item := range data.Items {
		// Create severity fail counters
		var criticalFailCount int
		var highFailCount int
		var mediumFailCount int
		var lowFailCount int
		var unknownFailCount int

		// Create map of map[id]Check
		checksMap := make(map[string]Check)

		// Loop through the spec of the report adding items to the map using the id number of the check as the key
		for _, specCheck := range item.Spec.Compliance.Controls {
			var ids []CheckID
			for _, checkID := range specCheck.Checks {
				ids = append(ids, CheckID{
					ID:  strings.ToUpper(checkID.ID),
					URL: fmt.Sprintf("https://avd.aquasec.com/misconfig/kubernetes/%s/", strings.ToLower(checkID.ID)),
				})
			}

			checksMap[specCheck.ID] = Check{
				IDNumber:    specCheck.ID,
				ID:          ids,
				Name:        specCheck.Name,
				Description: specCheck.Description,
				Severity:    string(specCheck.Severity),
			}
		}

		// Loop through status of report updating items in the map using the id number of the check as the key
		if item.Status.SummaryReport != nil {
			for _, statusCheck := range item.Status.SummaryReport.SummaryControls {
				check, ok := checksMap[statusCheck.ID]
				if !ok {
					continue
				}

				if statusCheck.TotalFail != nil {
					check.TotalFailed = statusCheck.TotalFail
					switch statusCheck.Severity {
					case "CRITICAL":
						criticalFailCount += *statusCheck.TotalFail
					case "HIGH":
						highFailCount += *statusCheck.TotalFail
					case "MEDIUM":
						mediumFailCount += *statusCheck.TotalFail
					case "LOW":
						lowFailCount += *statusCheck.TotalFail
					default:
						unknownFailCount += *statusCheck.TotalFail
					}
				}
				checksMap[statusCheck.ID] = check
			}
		}

		// Convert the map[id]Check to a []Check
		var checks []Check
		for _, check := range checksMap {
			checks = append(checks, check)
		}

		r = append(r, Data{
			ID:    item.Spec.Compliance.ID,
			Title: item.Spec.Compliance.Title,
			Summary: Summary{
				FailCount:         item.Status.Summary.FailCount,
				PassCount:         item.Status.Summary.PassCount,
				CriticalFailCount: criticalFailCount,
				HighFailCount:     highFailCount,
				MediumFailCount:   mediumFailCount,
				LowFailCount:      lowFailCount,
				UnknownFailCount:  unknownFailCount,
			},
			Checks: checks,
		})
	}

	return r
}

// GetSingleReportData converts some report data to the /compliancereport view
func GetSingleReportData(data *v1alpha1.ClusterComplianceReportList, id string, severity *string) Data {
	var r Data

	for _, item := range data.Items {
		// Make sure we're looking at the right report ID
		if item.Spec.Compliance.ID != id {
			continue
		}

		// Create map of map[id]Check
		checksMap := make(map[string]Check)

		// Loop through the spec of the report adding items to the map using the id number of the check as the key
		for _, specCheck := range item.Spec.Compliance.Controls {
			var ids []CheckID
			for _, checkID := range specCheck.Checks {
				ids = append(ids, CheckID{
					ID:  strings.ToUpper(checkID.ID),
					URL: fmt.Sprintf("https://avd.aquasec.com/misconfig/kubernetes/general/%s/", strings.ToLower(checkID.ID)),
				})
			}

			// If the severity filter was given, make sure we have the right severity for this check
			if severity != nil && *severity != string(specCheck.Severity) {
				continue
			}

			checksMap[specCheck.ID] = Check{
				IDNumber:    specCheck.ID,
				ID:          ids,
				Name:        specCheck.Name,
				Description: specCheck.Description,
				Severity:    string(specCheck.Severity),
			}
		}

		// Loop through status of report updating items in the map using the id number of the check as the key
		if item.Status.SummaryReport != nil {
			for _, statusCheck := range item.Status.SummaryReport.SummaryControls {
				check, ok := checksMap[statusCheck.ID]
				if !ok {
					continue
				}

				if statusCheck.TotalFail != nil {
					// Remove check if there's no failures anyway
					if *statusCheck.TotalFail == 0 {
						delete(checksMap, statusCheck.ID)
						continue
					}

					check.TotalFailed = statusCheck.TotalFail
				} else {
					// Remove check if there's not even a fail counter
					delete(checksMap, statusCheck.ID)
					continue
				}
				checksMap[statusCheck.ID] = check
			}
		}

		// Convert the map[id]Check to a []Check
		var checks []Check
		for _, check := range checksMap {
			checks = append(checks, check)
		}

		r = Data{
			ID:     item.Spec.Compliance.ID,
			Title:  item.Spec.Compliance.Title,
			Checks: checks,
		}
	}

	// Sort the r.Checks by Severity and then TotalFailed

	return r
}
