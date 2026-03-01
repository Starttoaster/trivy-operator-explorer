package agent

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/starttoaster/trivy-operator-explorer/internal/models"
)

// NormalizeVulnerabilityReports converts trivy-operator VulnerabilityReportList
// into the normalized model.
func NormalizeVulnerabilityReports(list *v1alpha1.VulnerabilityReportList) []models.VulnerabilityReport {
	var out []models.VulnerabilityReport
	for _, item := range list.Items {
		vr := models.VulnerabilityReport{
			Registry:          item.Report.Registry.Server,
			Repository:        item.Report.Artifact.Repository,
			Tag:               item.Report.Artifact.Tag,
			Digest:            item.Report.Artifact.Digest,
			OSFamily:          string(item.Report.OS.Family),
			OSVersion:         item.Report.OS.Name,
			OSEOSL:            item.Report.OS.Eosl,
			ResourceKind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			ResourceName:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
			ResourceNamespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
		}

		seen := make(map[string]struct{})
		for _, v := range item.Report.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.Resource
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			score := 0.0
			if v.Score != nil {
				score = *v.Score
			}
			vr.Vulnerabilities = append(vr.Vulnerabilities, models.Vulnerability{
				CVEID:            v.VulnerabilityID,
				Severity:         string(v.Severity),
				Score:            score,
				URL:              v.PrimaryLink,
				Resource:         v.Resource,
				Title:            v.Title,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
			})
		}

		out = append(out, vr)
	}
	return out
}

// NormalizeConfigAuditReports converts ConfigAuditReportList into the normalized model.
func NormalizeConfigAuditReports(list *v1alpha1.ConfigAuditReportList) []models.ConfigAuditReport {
	var out []models.ConfigAuditReport
	for _, item := range list.Items {
		name := resourceName(item.ObjectMeta.Labels, item.ObjectMeta.Annotations, item.Name)
		r := models.ConfigAuditReport{
			Name:      name,
			Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
			Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
		}
		for _, c := range item.Report.Checks {
			r.Checks = append(r.Checks, models.ConfigAuditCheck{
				ID:          c.ID,
				Severity:    string(c.Severity),
				Title:       c.Title,
				Description: c.Description,
			})
		}
		out = append(out, r)
	}
	return out
}

// NormalizeClusterInfraAuditReports converts ClusterInfraAssessmentReportList
// into the normalized model.
func NormalizeClusterInfraAuditReports(list *v1alpha1.ClusterInfraAssessmentReportList) []models.ClusterInfraAuditReport {
	var out []models.ClusterInfraAuditReport
	for _, item := range list.Items {
		name := resourceName(item.ObjectMeta.Labels, item.ObjectMeta.Annotations, item.Name)
		r := models.ClusterInfraAuditReport{
			Name: name,
			Kind: item.ObjectMeta.Labels["trivy-operator.resource.kind"],
		}
		for _, c := range item.Report.Checks {
			r.Checks = append(r.Checks, models.ClusterInfraAuditCheck{
				ID:          c.ID,
				Severity:    string(c.Severity),
				Title:       c.Title,
				Description: c.Description,
			})
		}
		out = append(out, r)
	}
	return out
}

// NormalizeRbacAssessmentReports converts RbacAssessmentReportList into the normalized model.
func NormalizeRbacAssessmentReports(list *v1alpha1.RbacAssessmentReportList) []models.RbacAssessmentReport {
	var out []models.RbacAssessmentReport
	for _, item := range list.Items {
		name := resourceName(item.ObjectMeta.Labels, item.ObjectMeta.Annotations, item.Name)
		r := models.RbacAssessmentReport{
			Name:      name,
			Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
			Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
		}
		for _, c := range item.Report.Checks {
			r.Checks = append(r.Checks, models.RbacAssessmentCheck{
				ID:          c.ID,
				Severity:    string(c.Severity),
				Title:       c.Title,
				Description: c.Description,
			})
		}
		out = append(out, r)
	}
	return out
}

// NormalizeClusterRbacAssessmentReports converts ClusterRbacAssessmentReportList
// into the normalized model.
func NormalizeClusterRbacAssessmentReports(list *v1alpha1.ClusterRbacAssessmentReportList) []models.ClusterRbacAssessmentReport {
	var out []models.ClusterRbacAssessmentReport
	for _, item := range list.Items {
		name := resourceName(item.ObjectMeta.Labels, item.ObjectMeta.Annotations, item.Name)
		r := models.ClusterRbacAssessmentReport{
			Name: name,
			Kind: item.ObjectMeta.Labels["trivy-operator.resource.kind"],
		}
		for _, c := range item.Report.Checks {
			r.Checks = append(r.Checks, models.ClusterRbacAssessmentCheck{
				ID:          c.ID,
				Severity:    string(c.Severity),
				Title:       c.Title,
				Description: c.Description,
			})
		}
		out = append(out, r)
	}
	return out
}

// NormalizeExposedSecretReports converts ExposedSecretReportList into the normalized model.
func NormalizeExposedSecretReports(list *v1alpha1.ExposedSecretReportList) []models.ExposedSecretReport {
	var out []models.ExposedSecretReport
	for _, item := range list.Items {
		imageName := formatImageName(
			item.Report.Registry.Server,
			item.Report.Artifact.Repository,
			item.Report.Artifact.Tag,
		)
		r := models.ExposedSecretReport{
			ImageName:         imageName,
			ImageDigest:       item.Report.Artifact.Digest,
			ResourceKind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			ResourceName:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
			ResourceNamespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
		}
		for _, s := range item.Report.Secrets {
			r.Secrets = append(r.Secrets, models.ExposedSecret{
				Severity: string(s.Severity),
				Title:    s.Title,
				Target:   s.Target,
				Match:    s.Match,
			})
		}
		out = append(out, r)
	}
	return out
}

// NormalizeComplianceReports converts ClusterComplianceReportList into the normalized model.
func NormalizeComplianceReports(list *v1alpha1.ClusterComplianceReportList) []models.ComplianceReport {
	var out []models.ComplianceReport
	for _, item := range list.Items {
		r := models.ComplianceReport{
			ReportID:  item.Spec.Compliance.ID,
			Title:     item.Spec.Compliance.Title,
			FailCount: item.Status.Summary.FailCount,
			PassCount: item.Status.Summary.PassCount,
		}

		controlMap := make(map[string]models.ComplianceControl)
		for _, specCtrl := range item.Spec.Compliance.Controls {
			var checkIDs []models.ComplianceCheckID
			for _, cid := range specCtrl.Checks {
				checkIDs = append(checkIDs, models.ComplianceCheckID{
					ID:  strings.ToUpper(cid.ID),
					URL: fmt.Sprintf("https://avd.aquasec.com/misconfig/kubernetes/%s/", strings.ToLower(cid.ID)),
				})
			}
			controlMap[specCtrl.ID] = models.ComplianceControl{
				IDNumber:    specCtrl.ID,
				CheckIDs:    checkIDs,
				Name:        specCtrl.Name,
				Description: specCtrl.Description,
				Severity:    string(specCtrl.Severity),
			}
		}

		if item.Status.SummaryReport != nil {
			for _, sc := range item.Status.SummaryReport.SummaryControls {
				if ctrl, ok := controlMap[sc.ID]; ok {
					if sc.TotalFail != nil {
						val := *sc.TotalFail
						ctrl.TotalFailed = &val
					}
					controlMap[sc.ID] = ctrl
				}
			}
		}

		for _, ctrl := range controlMap {
			r.Controls = append(r.Controls, ctrl)
		}
		out = append(out, r)
	}
	return out
}

func resourceName(labels, annotations map[string]string, fallback string) string {
	if val, ok := labels["trivy-operator.resource.name"]; ok {
		return val
	}
	if val, ok := annotations["trivy-operator.resource.name"]; ok {
		return val
	}
	return fallback
}

func formatImageName(registry, repo, tag string) string {
	if registry == "index.docker.io" {
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(repo, "library/"), tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}
