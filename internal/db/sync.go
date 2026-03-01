package db

import (
	"fmt"

	"github.com/starttoaster/trivy-operator-explorer/internal/models"
)

// SyncClusterReport upserts all data from a ClusterReport into the database.
// It uses a delete-and-reinsert strategy per resource type within a transaction.
func SyncClusterReport(report models.ClusterReport) error {
	clusterID, err := UpsertCluster(report.ClusterName)
	if err != nil {
		return fmt.Errorf("upserting cluster: %w", err)
	}

	tx, err := Client.Beginx()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// --- Vulnerability data ---
	if err := DeleteImageResourcesByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting image resources: %w", err)
	}
	for _, vr := range report.Vulnerabilities {
		imageID, err := UpsertImage(tx, vr.Registry, vr.Repository, vr.Tag, vr.Digest, vr.OSFamily, vr.OSVersion, vr.OSEOSL)
		if err != nil {
			return fmt.Errorf("upserting image: %w", err)
		}
		if err := InsertImageResource(tx, imageID, clusterID, vr.ResourceKind, vr.ResourceName, vr.ResourceNamespace); err != nil {
			return fmt.Errorf("inserting image resource: %w", err)
		}
		for _, v := range vr.Vulnerabilities {
			if err := UpsertVulnerability(tx, imageID, v.CVEID, v.Severity, v.Score, v.URL, v.Resource, v.Title, v.InstalledVersion, v.FixedVersion); err != nil {
				return fmt.Errorf("upserting vulnerability: %w", err)
			}
		}
	}

	// --- Config audits ---
	if err := DeleteConfigAuditsByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting config audits: %w", err)
	}
	for _, ca := range report.ConfigAudits {
		reportID, err := InsertConfigAuditReport(tx, clusterID, ca.Name, ca.Namespace, ca.Kind)
		if err != nil {
			return fmt.Errorf("inserting config audit report: %w", err)
		}
		for _, check := range ca.Checks {
			if err := InsertConfigAuditCheck(tx, reportID, check.ID, check.Severity, check.Title, check.Description); err != nil {
				return fmt.Errorf("inserting config audit check: %w", err)
			}
		}
	}

	// --- Cluster infra audits ---
	if err := DeleteClusterInfraAuditsByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting cluster infra audits: %w", err)
	}
	for _, cia := range report.ClusterInfraAudits {
		reportID, err := InsertClusterInfraAuditReport(tx, clusterID, cia.Name, cia.Kind)
		if err != nil {
			return fmt.Errorf("inserting cluster infra audit report: %w", err)
		}
		for _, check := range cia.Checks {
			if err := InsertClusterInfraAuditCheck(tx, reportID, check.ID, check.Severity, check.Title, check.Description); err != nil {
				return fmt.Errorf("inserting cluster infra audit check: %w", err)
			}
		}
	}

	// --- RBAC assessments ---
	if err := DeleteRbacAssessmentsByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting rbac assessments: %w", err)
	}
	for _, ra := range report.RbacAssessments {
		reportID, err := InsertRbacAssessmentReport(tx, clusterID, ra.Name, ra.Namespace, ra.Kind)
		if err != nil {
			return fmt.Errorf("inserting rbac assessment report: %w", err)
		}
		for _, check := range ra.Checks {
			if err := InsertRbacAssessmentCheck(tx, reportID, check.ID, check.Severity, check.Title, check.Description); err != nil {
				return fmt.Errorf("inserting rbac assessment check: %w", err)
			}
		}
	}

	// --- Cluster RBAC assessments ---
	if err := DeleteClusterRbacAssessmentsByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting cluster rbac assessments: %w", err)
	}
	for _, cra := range report.ClusterRbacAssessments {
		reportID, err := InsertClusterRbacAssessmentReport(tx, clusterID, cra.Name, cra.Kind)
		if err != nil {
			return fmt.Errorf("inserting cluster rbac assessment report: %w", err)
		}
		for _, check := range cra.Checks {
			if err := InsertClusterRbacAssessmentCheck(tx, reportID, check.ID, check.Severity, check.Title, check.Description); err != nil {
				return fmt.Errorf("inserting cluster rbac assessment check: %w", err)
			}
		}
	}

	// --- Exposed secrets ---
	if err := DeleteExposedSecretsByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting exposed secrets: %w", err)
	}
	for _, es := range report.ExposedSecrets {
		reportID, err := InsertExposedSecretReport(tx, clusterID, es.ImageName, es.ImageDigest, es.ResourceKind, es.ResourceName, es.ResourceNamespace)
		if err != nil {
			return fmt.Errorf("inserting exposed secret report: %w", err)
		}
		for _, s := range es.Secrets {
			if err := InsertExposedSecret(tx, reportID, s.Severity, s.Title, s.Target, s.Match); err != nil {
				return fmt.Errorf("inserting exposed secret: %w", err)
			}
		}
	}

	// --- Compliance reports ---
	if err := DeleteComplianceByCluster(tx, clusterID); err != nil {
		return fmt.Errorf("deleting compliance: %w", err)
	}
	for _, cr := range report.ComplianceReports {
		dbReportID, err := InsertComplianceReport(tx, clusterID, cr.ReportID, cr.Title, cr.FailCount, cr.PassCount)
		if err != nil {
			return fmt.Errorf("inserting compliance report: %w", err)
		}
		for _, control := range cr.Controls {
			if err := InsertComplianceCheck(tx, dbReportID, control); err != nil {
				return fmt.Errorf("inserting compliance check: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}
