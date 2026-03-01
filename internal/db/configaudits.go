package db

import (
	"github.com/jmoiron/sqlx"
)

// ConfigAuditReportRow represents a row in the config_audit_reports table.
type ConfigAuditReportRow struct {
	ID        int    `db:"id"`
	ClusterID int    `db:"cluster_id"`
	Name      string `db:"name"`
	Namespace string `db:"namespace"`
	Kind      string `db:"kind"`
}

// ConfigAuditCheckRow represents a row in the config_audit_checks table.
type ConfigAuditCheckRow struct {
	ID          int    `db:"id"`
	ReportID    int    `db:"report_id"`
	CheckID     string `db:"check_id"`
	Severity    string `db:"severity"`
	Title       string `db:"title"`
	Description string `db:"description"`
}

// DeleteConfigAuditsByCluster removes all config audit data for a cluster.
func DeleteConfigAuditsByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(
		`DELETE FROM config_audit_checks WHERE report_id IN
		   (SELECT id FROM config_audit_reports WHERE cluster_id = $1)`, clusterID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM config_audit_reports WHERE cluster_id = $1`, clusterID)
	return err
}

// InsertConfigAuditReport inserts a report and returns its ID.
func InsertConfigAuditReport(tx *sqlx.Tx, clusterID int, name, namespace, kind string) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO config_audit_reports (cluster_id, name, namespace, kind)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		clusterID, name, namespace, kind,
	).Scan(&id)
	return id, err
}

// InsertConfigAuditCheck inserts a check for a report.
func InsertConfigAuditCheck(tx *sqlx.Tx, reportID int, checkID, severity, title, description string) error {
	_, err := tx.Exec(
		`INSERT INTO config_audit_checks (report_id, check_id, severity, title, description)
		 VALUES ($1, $2, $3, $4, $5)`,
		reportID, checkID, severity, title, description,
	)
	return err
}

// ConfigAuditReportWithCluster is a joined view including cluster name.
type ConfigAuditReportWithCluster struct {
	ConfigAuditReportRow
	ClusterName string `db:"cluster_name"`
}

// GetAllConfigAuditReports returns all config audit reports with cluster info.
func GetAllConfigAuditReports() ([]ConfigAuditReportWithCluster, error) {
	var rows []ConfigAuditReportWithCluster
	err := Client.Select(&rows,
		`SELECT r.id, r.cluster_id, r.name, r.namespace, r.kind, c.name AS cluster_name
		 FROM config_audit_reports r
		 JOIN clusters c ON c.id = r.cluster_id
		 ORDER BY r.namespace, r.name`)
	return rows, err
}

// GetConfigAuditChecks returns all checks for a report.
func GetConfigAuditChecks(reportID int) ([]ConfigAuditCheckRow, error) {
	var rows []ConfigAuditCheckRow
	err := Client.Select(&rows,
		`SELECT id, report_id, check_id, severity, title, description
		 FROM config_audit_checks WHERE report_id = $1`,
		reportID,
	)
	return rows, err
}
