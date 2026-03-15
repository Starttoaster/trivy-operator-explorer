package db

import (
	"github.com/jmoiron/sqlx"
)

// ClusterInfraAuditReportRow represents a row in the cluster_infra_audit_reports table.
type ClusterInfraAuditReportRow struct {
	ID        int    `db:"id"`
	ClusterID int    `db:"cluster_id"`
	Name      string `db:"name"`
	Kind      string `db:"kind"`
}

// ClusterInfraAuditCheckRow represents a row in the cluster_infra_audit_checks table.
type ClusterInfraAuditCheckRow struct {
	ID          int    `db:"id"`
	ReportID    int    `db:"report_id"`
	CheckID     string `db:"check_id"`
	Severity    string `db:"severity"`
	Title       string `db:"title"`
	Description string `db:"description"`
}

// DeleteClusterInfraAuditsByCluster removes all cluster infra audit data for a cluster.
func DeleteClusterInfraAuditsByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(
		`DELETE FROM cluster_infra_audit_checks WHERE report_id IN
		   (SELECT id FROM cluster_infra_audit_reports WHERE cluster_id = $1)`, clusterID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM cluster_infra_audit_reports WHERE cluster_id = $1`, clusterID)
	return err
}

// InsertClusterInfraAuditReport inserts a report and returns its ID.
func InsertClusterInfraAuditReport(tx *sqlx.Tx, clusterID int, name, kind string) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO cluster_infra_audit_reports (cluster_id, name, kind)
		 VALUES ($1, $2, $3) RETURNING id`,
		clusterID, name, kind,
	).Scan(&id)
	return id, err
}

// InsertClusterInfraAuditCheck inserts a check for a report.
func InsertClusterInfraAuditCheck(tx *sqlx.Tx, reportID int, checkID, severity, title, description string) error {
	_, err := tx.Exec(
		`INSERT INTO cluster_infra_audit_checks (report_id, check_id, severity, title, description)
		 VALUES ($1, $2, $3, $4, $5)`,
		reportID, checkID, severity, title, description,
	)
	return err
}

// ClusterInfraAuditReportWithCluster is a joined view including cluster name.
type ClusterInfraAuditReportWithCluster struct {
	ClusterInfraAuditReportRow
	ClusterName string `db:"cluster_name"`
}

// GetAllClusterInfraAuditReports returns all cluster infra audit reports.
func GetAllClusterInfraAuditReports() ([]ClusterInfraAuditReportWithCluster, error) {
	var rows []ClusterInfraAuditReportWithCluster
	err := Client.Select(&rows,
		`SELECT r.id, r.cluster_id, r.name, r.kind, c.name AS cluster_name
		 FROM cluster_infra_audit_reports r
		 JOIN clusters c ON c.id = r.cluster_id
		 ORDER BY r.name`)
	return rows, err
}

// GetClusterInfraAuditChecks returns all checks for a report.
func GetClusterInfraAuditChecks(reportID int) ([]ClusterInfraAuditCheckRow, error) {
	var rows []ClusterInfraAuditCheckRow
	err := Client.Select(&rows,
		`SELECT id, report_id, check_id, severity, title, description
		 FROM cluster_infra_audit_checks WHERE report_id = $1`,
		reportID,
	)
	return rows, err
}
