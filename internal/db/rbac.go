package db

import (
	"github.com/jmoiron/sqlx"
)

// RbacAssessmentReportRow represents a row in the rbac_assessment_reports table.
type RbacAssessmentReportRow struct {
	ID        int    `db:"id"`
	ClusterID int    `db:"cluster_id"`
	Name      string `db:"name"`
	Namespace string `db:"namespace"`
	Kind      string `db:"kind"`
}

// RbacAssessmentCheckRow represents a row in the rbac_assessment_checks table.
type RbacAssessmentCheckRow struct {
	ID          int    `db:"id"`
	ReportID    int    `db:"report_id"`
	CheckID     string `db:"check_id"`
	Severity    string `db:"severity"`
	Title       string `db:"title"`
	Description string `db:"description"`
}

// DeleteRbacAssessmentsByCluster removes all RBAC assessment data for a cluster.
func DeleteRbacAssessmentsByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(
		`DELETE FROM rbac_assessment_checks WHERE report_id IN
		   (SELECT id FROM rbac_assessment_reports WHERE cluster_id = $1)`, clusterID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM rbac_assessment_reports WHERE cluster_id = $1`, clusterID)
	return err
}

// InsertRbacAssessmentReport inserts a report and returns its ID.
func InsertRbacAssessmentReport(tx *sqlx.Tx, clusterID int, name, namespace, kind string) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO rbac_assessment_reports (cluster_id, name, namespace, kind)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		clusterID, name, namespace, kind,
	).Scan(&id)
	return id, err
}

// InsertRbacAssessmentCheck inserts a check for a report.
func InsertRbacAssessmentCheck(tx *sqlx.Tx, reportID int, checkID, severity, title, description string) error {
	_, err := tx.Exec(
		`INSERT INTO rbac_assessment_checks (report_id, check_id, severity, title, description)
		 VALUES ($1, $2, $3, $4, $5)`,
		reportID, checkID, severity, title, description,
	)
	return err
}

// --- Cluster-scoped RBAC ---

// ClusterRbacAssessmentReportRow represents a row in the cluster_rbac_assessment_reports table.
type ClusterRbacAssessmentReportRow struct {
	ID        int    `db:"id"`
	ClusterID int    `db:"cluster_id"`
	Name      string `db:"name"`
	Kind      string `db:"kind"`
}

// ClusterRbacAssessmentCheckRow represents a row in the cluster_rbac_assessment_checks table.
type ClusterRbacAssessmentCheckRow struct {
	ID          int    `db:"id"`
	ReportID    int    `db:"report_id"`
	CheckID     string `db:"check_id"`
	Severity    string `db:"severity"`
	Title       string `db:"title"`
	Description string `db:"description"`
}

// DeleteClusterRbacAssessmentsByCluster removes all cluster RBAC assessment data for a cluster.
func DeleteClusterRbacAssessmentsByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(
		`DELETE FROM cluster_rbac_assessment_checks WHERE report_id IN
		   (SELECT id FROM cluster_rbac_assessment_reports WHERE cluster_id = $1)`, clusterID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM cluster_rbac_assessment_reports WHERE cluster_id = $1`, clusterID)
	return err
}

// InsertClusterRbacAssessmentReport inserts a report and returns its ID.
func InsertClusterRbacAssessmentReport(tx *sqlx.Tx, clusterID int, name, kind string) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO cluster_rbac_assessment_reports (cluster_id, name, kind)
		 VALUES ($1, $2, $3) RETURNING id`,
		clusterID, name, kind,
	).Scan(&id)
	return id, err
}

// InsertClusterRbacAssessmentCheck inserts a check for a report.
func InsertClusterRbacAssessmentCheck(tx *sqlx.Tx, reportID int, checkID, severity, title, description string) error {
	_, err := tx.Exec(
		`INSERT INTO cluster_rbac_assessment_checks (report_id, check_id, severity, title, description)
		 VALUES ($1, $2, $3, $4, $5)`,
		reportID, checkID, severity, title, description,
	)
	return err
}

// RbacAssessmentReportWithCluster is a joined view including cluster name.
type RbacAssessmentReportWithCluster struct {
	RbacAssessmentReportRow
	ClusterName string `db:"cluster_name"`
}

// GetAllRbacAssessmentReports returns all RBAC assessment reports.
func GetAllRbacAssessmentReports() ([]RbacAssessmentReportWithCluster, error) {
	var rows []RbacAssessmentReportWithCluster
	err := Client.Select(&rows,
		`SELECT r.id, r.cluster_id, r.name, r.namespace, r.kind, c.name AS cluster_name
		 FROM rbac_assessment_reports r
		 JOIN clusters c ON c.id = r.cluster_id
		 ORDER BY r.namespace, r.name`)
	return rows, err
}

// GetRbacAssessmentChecks returns all checks for a report.
func GetRbacAssessmentChecks(reportID int) ([]RbacAssessmentCheckRow, error) {
	var rows []RbacAssessmentCheckRow
	err := Client.Select(&rows,
		`SELECT id, report_id, check_id, severity, title, description
		 FROM rbac_assessment_checks WHERE report_id = $1`,
		reportID,
	)
	return rows, err
}

// ClusterRbacAssessmentReportWithCluster is a joined view including cluster name.
type ClusterRbacAssessmentReportWithCluster struct {
	ClusterRbacAssessmentReportRow
	ClusterName string `db:"cluster_name"`
}

// GetAllClusterRbacAssessmentReports returns all cluster RBAC assessment reports.
func GetAllClusterRbacAssessmentReports() ([]ClusterRbacAssessmentReportWithCluster, error) {
	var rows []ClusterRbacAssessmentReportWithCluster
	err := Client.Select(&rows,
		`SELECT r.id, r.cluster_id, r.name, r.kind, c.name AS cluster_name
		 FROM cluster_rbac_assessment_reports r
		 JOIN clusters c ON c.id = r.cluster_id
		 ORDER BY r.name`)
	return rows, err
}

// GetClusterRbacAssessmentChecks returns all checks for a report.
func GetClusterRbacAssessmentChecks(reportID int) ([]ClusterRbacAssessmentCheckRow, error) {
	var rows []ClusterRbacAssessmentCheckRow
	err := Client.Select(&rows,
		`SELECT id, report_id, check_id, severity, title, description
		 FROM cluster_rbac_assessment_checks WHERE report_id = $1`,
		reportID,
	)
	return rows, err
}
