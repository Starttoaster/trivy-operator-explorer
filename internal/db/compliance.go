package db

import (
	"encoding/json"

	"github.com/jmoiron/sqlx"
	"github.com/starttoaster/trivy-operator-explorer/internal/models"
)

// ComplianceReportRow represents a row in the compliance_reports table.
type ComplianceReportRow struct {
	ID        int    `db:"id"`
	ClusterID int    `db:"cluster_id"`
	ReportID  string `db:"report_id"`
	Title     string `db:"title"`
	FailCount int    `db:"fail_count"`
	PassCount int    `db:"pass_count"`
}

// ComplianceCheckRow represents a row in the compliance_checks table.
type ComplianceCheckRow struct {
	ID          int    `db:"id"`
	ReportID    int    `db:"report_id"`
	CheckID     string `db:"check_id"`
	CheckIDs    []byte `db:"check_ids"`
	Name        string `db:"name"`
	Description string `db:"description"`
	Severity    string `db:"severity"`
	TotalFailed *int   `db:"total_failed"`
}

// DeleteComplianceByCluster removes all compliance data for a cluster.
func DeleteComplianceByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(
		`DELETE FROM compliance_checks WHERE report_id IN
		   (SELECT id FROM compliance_reports WHERE cluster_id = $1)`, clusterID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM compliance_reports WHERE cluster_id = $1`, clusterID)
	return err
}

// InsertComplianceReport inserts a compliance report and returns its ID.
func InsertComplianceReport(tx *sqlx.Tx, clusterID int, reportID, title string, failCount, passCount int) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO compliance_reports (cluster_id, report_id, title, fail_count, pass_count)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		clusterID, reportID, title, failCount, passCount,
	).Scan(&id)
	return id, err
}

// InsertComplianceCheck inserts a compliance check for a report.
func InsertComplianceCheck(tx *sqlx.Tx, dbReportID int, control models.ComplianceControl) error {
	checkIDsJSON, err := json.Marshal(control.CheckIDs)
	if err != nil {
		return err
	}

	_, err = tx.Exec(
		`INSERT INTO compliance_checks (report_id, check_id, check_ids, name, description, severity, total_failed)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		dbReportID, control.IDNumber, checkIDsJSON, control.Name, control.Description, control.Severity, control.TotalFailed,
	)
	return err
}

// ComplianceReportWithCluster is a joined view including cluster name.
type ComplianceReportWithCluster struct {
	ComplianceReportRow
	ClusterName string `db:"cluster_name"`
}

// GetAllComplianceReports returns all compliance reports with cluster info.
func GetAllComplianceReports() ([]ComplianceReportWithCluster, error) {
	var rows []ComplianceReportWithCluster
	err := Client.Select(&rows,
		`SELECT r.id, r.cluster_id, r.report_id, r.title, r.fail_count, r.pass_count, c.name AS cluster_name
		 FROM compliance_reports r
		 JOIN clusters c ON c.id = r.cluster_id
		 ORDER BY r.title`)
	return rows, err
}

// GetComplianceChecks returns all checks for a compliance report.
func GetComplianceChecks(reportID int) ([]ComplianceCheckRow, error) {
	var rows []ComplianceCheckRow
	err := Client.Select(&rows,
		`SELECT id, report_id, check_id, check_ids, name, description, severity, total_failed
		 FROM compliance_checks WHERE report_id = $1`,
		reportID,
	)
	return rows, err
}

// ParseCheckIDs unmarshals the JSONB check_ids column.
func ParseCheckIDs(raw []byte) ([]models.ComplianceCheckID, error) {
	var ids []models.ComplianceCheckID
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}
