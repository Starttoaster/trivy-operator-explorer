package roles

import (
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// Filters represents the available optional filters to the config audit view
type Filters struct {
	Namespace string
	Kind      string
}

// GetView converts some report data to the /roles view
func GetView(data *v1alpha1.ConfigAuditReportList, filters Filters) View {
	var view View

	for _, item := range data.Items {
		var name string
		if val, ok := item.ObjectMeta.Labels["trivy-operator.resource.name"]; ok {
			name = val
		} else if val, ok := item.ObjectMeta.Annotations["trivy-operator.resource.name"]; ok {
			name = val
		} else {
			name = item.Name
		}
		kind := item.ObjectMeta.Labels["trivy-operator.resource.kind"]
		namespace := item.ObjectMeta.Labels["trivy-operator.resource.namespace"]

		if filters.Kind != "" {
			if kind != filters.Kind {
				continue
			}
		}
		if filters.Namespace != "" {
			if namespace != filters.Namespace {
				continue
			}
		}

		audit := Data{
			Kind:      kind,
			Name:      name,
			Namespace: namespace,
		}

		index, unique := view.isUnique(audit.Name, audit.Namespace, audit.Kind)
		if unique {
			view = append(view, audit)
			index = len(view) - 1
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
				view[index].CriticalVulnerabilities = append(view[index].CriticalVulnerabilities, vuln)
			case "high":
				view[index].HighVulnerabilities = append(view[index].HighVulnerabilities, vuln)
			case "medium":
				view[index].MediumVulnerabilities = append(view[index].MediumVulnerabilities, vuln)
			case "low":
				view[index].LowVulnerabilities = append(view[index].LowVulnerabilities, vuln)
			}
		}
	}

	view = sortView(view)

	return view
}

func (a View) isUnique(name, namespace, kind string) (int, bool) {
	for i, audit := range a {
		if name == audit.Name && kind == audit.Kind {
			return i, false
		}
	}

	return 0, true
}

func sortView(a View) View {
	// Sort the slice by severity in descending order
	sort.Slice(a, func(j, k int) bool {
		if len(a[j].CriticalVulnerabilities) != len(a[k].CriticalVulnerabilities) {
			return len(a[j].CriticalVulnerabilities) > len(a[k].CriticalVulnerabilities)
		}

		if len(a[j].HighVulnerabilities) != len(a[k].HighVulnerabilities) {
			return len(a[j].HighVulnerabilities) > len(a[k].HighVulnerabilities)
		}

		if len(a[j].MediumVulnerabilities) != len(a[k].MediumVulnerabilities) {
			return len(a[j].MediumVulnerabilities) > len(a[k].MediumVulnerabilities)
		}

		return len(a[j].LowVulnerabilities) > len(a[k].LowVulnerabilities)
	})

	return a
}
