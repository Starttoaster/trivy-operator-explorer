package role

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters contains the supported filters for the image view
type Filters struct {
	Name      string
	Namespace string

	// optional
	Severity string
}

// GetView converts some report data to the /role view
// returns view data and "true" if the image was found in the report list
func GetView(data *v1alpha1.RbacAssessmentReportList, filters Filters) (View, bool) {
	for _, item := range data.Items {
		var name string
		if val, ok := item.ObjectMeta.Labels["trivy-operator.resource.name"]; ok {
			name = val
		} else if val, ok := item.ObjectMeta.Annotations["trivy-operator.resource.name"]; ok {
			name = val
		} else {
			name = item.Name
		}

		if filters.Name != name && filters.Namespace != item.ObjectMeta.Labels["trivy-operator.resource.namespace"] {
			continue
		}

		role := View{
			Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name:      name,
			Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
		}

		for _, v := range item.Report.Checks {
			ksvNum := strings.TrimPrefix(v.ID, "KSV")
			url := fmt.Sprintf("https://avd.aquasec.com/misconfig/kubernetes/general/avd-ksv-%04s/", ksvNum)

			vuln := Vulnerability{
				ID:          v.ID,
				URL:         url,
				Severity:    string(v.Severity),
				Title:       v.Title,
				Description: v.Description,
			}

			if filters.Severity != "" && !strings.EqualFold(vuln.Severity, filters.Severity) {
				continue
			}

			role.Vulnerabilities = append(role.Vulnerabilities, vuln)
		}

		role = sortView(role)

		return role, true
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
	sort.Slice(v.Vulnerabilities, func(j, k int) bool {
		return severityOrder[v.Vulnerabilities[j].Severity] > severityOrder[v.Vulnerabilities[k].Severity]
	})

	return v
}
