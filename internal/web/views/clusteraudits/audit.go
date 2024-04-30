package clusteraudits

import (
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// GetView converts some report data to the /roles view
func GetView(data *v1alpha1.ClusterInfraAssessmentReportList) View {
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

		audit := Data{
			Kind: item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name: name,
		}

		index, unique := view.isUnique(audit.Name, audit.Kind)
		if unique {
			view = append(view, audit)
			index = len(view) - 1
		}

		for _, v := range item.Report.Checks {
			severity := v.Severity
			check := Check{
				ID:          v.ID,
				Title:       v.Title,
				Description: v.Description,
			}

			switch strings.ToLower(string(severity)) {
			case "critical":
				view[index].CriticalChecks = append(view[index].CriticalChecks, check)
			case "high":
				view[index].HighChecks = append(view[index].HighChecks, check)
			case "medium":
				view[index].MediumChecks = append(view[index].MediumChecks, check)
			case "low":
				view[index].LowChecks = append(view[index].LowChecks, check)
			}
		}
	}

	view = sortView(view)

	return view
}

func (a View) isUnique(name, kind string) (int, bool) {
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
		if len(a[j].CriticalChecks) != len(a[k].CriticalChecks) {
			return len(a[j].CriticalChecks) > len(a[k].CriticalChecks)
		}

		if len(a[j].HighChecks) != len(a[k].HighChecks) {
			return len(a[j].HighChecks) > len(a[k].HighChecks)
		}

		if len(a[j].MediumChecks) != len(a[k].MediumChecks) {
			return len(a[j].MediumChecks) > len(a[k].MediumChecks)
		}

		return len(a[j].LowChecks) > len(a[k].LowChecks)
	})

	return a
}
