package clusteraudit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters contains the supported filters for the configaudit view
type Filters struct {
	Name string
	Kind string

	// optional
	Severity string
}

// GetView converts some report data to the /configaudit view
// returns view data and "true" if the image was found in the report list
func GetView(data *v1alpha1.ClusterInfraAssessmentReportList, filters Filters) (View, bool) {
	for _, item := range data.Items {
		var name string
		if val, ok := item.ObjectMeta.Labels["trivy-operator.resource.name"]; ok {
			name = val
		} else if val, ok := item.ObjectMeta.Annotations["trivy-operator.resource.name"]; ok {
			name = val
		} else {
			name = item.Name
		}

		if filters.Name != name {
			continue
		}
		if filters.Kind != item.ObjectMeta.Labels["trivy-operator.resource.kind"] {
			continue
		}

		view := View{
			Kind: item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name: name,
		}

		for _, v := range item.Report.Checks {
			ksvNum := strings.TrimPrefix(v.ID, "KSV")
			url := fmt.Sprintf("https://avd.aquasec.com/misconfig/kubernetes/general/avd-kcv-%04s/", strings.TrimPrefix(ksvNum, "KCV"))

			check := Check{
				ID:          v.ID,
				URL:         url,
				Severity:    string(v.Severity),
				Title:       v.Title,
				Description: v.Description,
				Remediation: v.Remediation,
			}

			if filters.Severity != "" && !strings.EqualFold(check.Severity, filters.Severity) {
				continue
			}

			view.Checks = append(view.Checks, check)
		}

		view = sortView(view)

		return view, true
	}

	return View{}, false
}

func sortView(v View) View {
	// Create an order for severities to sort by
	// Define custom priority order
	severityOrder := map[string]int{
		"CRITICAL": 3,
		"HIGH":     2,
		"MEDIUM":   1,
		"LOW":      0,
	}

	// Sort the slice by severity in descending order
	sort.Slice(v.Checks, func(j, k int) bool {
		return severityOrder[v.Checks[j].Severity] > severityOrder[v.Checks[k].Severity]
	})

	return v
}
