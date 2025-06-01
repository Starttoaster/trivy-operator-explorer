package compliance

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// GetView converts some report data to the /compliance view
func GetView(data *v1alpha1.ClusterComplianceReportList) View {
	var r View

	for _, item := range data.Items {
		// Create map of map[id]Check
		checksMap := make(map[string]Check)

		// Loop through the spec of the report adding items to the map using the id number of the check as the key
		for _, specCheck := range item.Spec.Compliance.Controls {
			var ids []string
			for _, checkID := range specCheck.Checks {
				ids = append(ids, checkID.ID)
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
			continue
		}
		for _, statusCheck := range item.Status.SummaryReport.SummaryControls {
			check, ok := checksMap[statusCheck.ID]
			if !ok {
				continue
			}
			if statusCheck.TotalFail != nil {
				check.TotalFailed = statusCheck.TotalFail
			}
		}

		// Convert the map[id]Check to a []Check
		var checks []Check
		for _, check := range checksMap {
			checks = append(checks, check)
		}

		// Sort the []Check by Severity and then TotalFailed

		r = append(r, Data{
			ID:    item.Spec.Compliance.ID,
			Title: item.Spec.Compliance.Title,
			Summary: Summary{
				FailCount: item.Status.Summary.FailCount,
				PassCount: item.Status.Summary.PassCount,
			},
			Checks: checks,
		})
	}

	return r
}
