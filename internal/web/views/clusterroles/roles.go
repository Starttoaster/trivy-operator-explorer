package roles

import (
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// GetView converts some report data to the /roles view
func GetView(data *v1alpha1.ClusterRbacAssessmentReportList) View {
	var r View

	for _, item := range data.Items {
		var name string
		if val, ok := item.ObjectMeta.Labels["trivy-operator.resource.name"]; ok {
			name = val
		} else if val, ok := item.ObjectMeta.Annotations["trivy-operator.resource.name"]; ok {
			name = val
		} else {
			name = item.Name
		}

		role := Data{
			Kind: item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name: name,
		}

		index, unique := r.isUniqueRole(role.Name, role.Kind)
		if unique {
			r = append(r, role)
			index = len(r) - 1
		}

		for _, v := range item.Report.Checks {
			severity := v.Severity
			vuln := Vulnerability{
				ID:          v.ID,
				Title:       v.Title,
				Description: v.Description,
			}

			switch strings.ToLower(string(severity)) {
			case "critical":
				r[index].CriticalVulnerabilities = append(r[index].CriticalVulnerabilities, vuln)
			case "high":
				r[index].HighVulnerabilities = append(r[index].HighVulnerabilities, vuln)
			case "medium":
				r[index].MediumVulnerabilities = append(r[index].MediumVulnerabilities, vuln)
			case "low":
				r[index].LowVulnerabilities = append(r[index].LowVulnerabilities, vuln)
			}
		}
	}

	r = sortView(r)

	return r
}

func (r View) isUniqueRole(name, kind string) (int, bool) {
	for i, role := range r {
		if name == role.Name && kind == role.Kind {
			return i, false
		}
	}

	return 0, true
}

func sortView(r View) View {
	// Sort the slice by severity in descending order
	sort.Slice(r, func(j, k int) bool {
		if len(r[j].CriticalVulnerabilities) != len(r[k].CriticalVulnerabilities) {
			return len(r[j].CriticalVulnerabilities) > len(r[k].CriticalVulnerabilities)
		}

		if len(r[j].HighVulnerabilities) != len(r[k].HighVulnerabilities) {
			return len(r[j].HighVulnerabilities) > len(r[k].HighVulnerabilities)
		}

		if len(r[j].MediumVulnerabilities) != len(r[k].MediumVulnerabilities) {
			return len(r[j].MediumVulnerabilities) > len(r[k].MediumVulnerabilities)
		}

		return len(r[j].LowVulnerabilities) > len(r[k].LowVulnerabilities)
	})

	return r
}
