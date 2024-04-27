package role

import (
	"sort"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/views"
)

// GetRolesView converts some scrape data to the /roles view
func GetRolesView(data *scraper.ScrapeData) RolesView {
	var r RolesView

	for _, gauge := range data.Gauges {
		if gauge.Key == views.TrivyRbacAssessmentMetricName {
			// TODO -- grab each label into variables individually and check that they're not empty
			// Construct all data types from metric data
			role := RoleData{
				Name:      gauge.Labels["name"],
				Namespace: gauge.Labels["namespace"],
				Kind:      gauge.Labels["resource_kind"],
			}
			severity := gauge.Labels["severity"]
			vuln := Vulnerability{
				ID:          gauge.Labels["rbac_assessment_id"],
				Title:       gauge.Labels["rbac_assessment_title"],
				Description: gauge.Labels["rbac_assessment_description"],
			}

			index, unique := r.isUniqueRole(role.Name, role.Namespace, role.Kind)

			if unique {
				switch severity {
				case "Critical":
					role.CriticalVulnerabilities = append(role.CriticalVulnerabilities, vuln)
				case "High":
					role.HighVulnerabilities = append(role.HighVulnerabilities, vuln)
				case "Medium":
					role.MediumVulnerabilities = append(role.MediumVulnerabilities, vuln)
				case "Low":
					role.LowVulnerabilities = append(role.LowVulnerabilities, vuln)
				}
				r = append(r, role)
			} else {
				switch severity {
				case "Critical":
					r[index].CriticalVulnerabilities = append(r[index].CriticalVulnerabilities, vuln)
				case "High":
					r[index].HighVulnerabilities = append(r[index].HighVulnerabilities, vuln)
				case "Medium":
					r[index].MediumVulnerabilities = append(r[index].MediumVulnerabilities, vuln)
				case "Low":
					r[index].LowVulnerabilities = append(r[index].LowVulnerabilities, vuln)
				}
			}
		}
	}

	r = sortRolesView(r)

	return r
}

func (r RolesView) isUniqueRole(name, namespace, kind string) (int, bool) {
	for i, role := range r {
		if name == role.Name && namespace == role.Namespace && kind == role.Kind {
			return i, false
		}
	}

	return 0, true
}

func sortRolesView(r RolesView) RolesView {
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
