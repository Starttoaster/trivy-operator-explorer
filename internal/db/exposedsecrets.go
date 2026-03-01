package db

import (
	"github.com/jmoiron/sqlx"
)

// ExposedSecretReportRow represents a row in the exposed_secret_reports table.
type ExposedSecretReportRow struct {
	ID                int    `db:"id"`
	ClusterID         int    `db:"cluster_id"`
	ImageName         string `db:"image_name"`
	ImageDigest       string `db:"image_digest"`
	ResourceKind      string `db:"resource_kind"`
	ResourceName      string `db:"resource_name"`
	ResourceNamespace string `db:"resource_namespace"`
}

// ExposedSecretRow represents a row in the exposed_secrets table.
type ExposedSecretRow struct {
	ID       int    `db:"id"`
	ReportID int    `db:"report_id"`
	Severity string `db:"severity"`
	Title    string `db:"title"`
	Target   string `db:"target"`
	Match    string `db:"match"`
}

// DeleteExposedSecretsByCluster removes all exposed secret data for a cluster.
func DeleteExposedSecretsByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(
		`DELETE FROM exposed_secrets WHERE report_id IN
		   (SELECT id FROM exposed_secret_reports WHERE cluster_id = $1)`, clusterID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM exposed_secret_reports WHERE cluster_id = $1`, clusterID)
	return err
}

// InsertExposedSecretReport inserts a report and returns its ID.
func InsertExposedSecretReport(tx *sqlx.Tx, clusterID int, imageName, imageDigest, resourceKind, resourceName, resourceNamespace string) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO exposed_secret_reports (cluster_id, image_name, image_digest, resource_kind, resource_name, resource_namespace)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		clusterID, imageName, imageDigest, resourceKind, resourceName, resourceNamespace,
	).Scan(&id)
	return id, err
}

// InsertExposedSecret inserts a secret finding for a report.
func InsertExposedSecret(tx *sqlx.Tx, reportID int, severity, title, target, match string) error {
	_, err := tx.Exec(
		`INSERT INTO exposed_secrets (report_id, severity, title, target, match)
		 VALUES ($1, $2, $3, $4, $5)`,
		reportID, severity, title, target, match,
	)
	return err
}

// ExposedSecretReportWithCluster is a joined view including cluster name.
type ExposedSecretReportWithCluster struct {
	ExposedSecretReportRow
	ClusterName string `db:"cluster_name"`
}

// GetAllExposedSecretReports returns all exposed secret reports with cluster info.
func GetAllExposedSecretReports() ([]ExposedSecretReportWithCluster, error) {
	var rows []ExposedSecretReportWithCluster
	err := Client.Select(&rows,
		`SELECT r.id, r.cluster_id, r.image_name, r.image_digest,
		        r.resource_kind, r.resource_name, r.resource_namespace,
		        c.name AS cluster_name
		 FROM exposed_secret_reports r
		 JOIN clusters c ON c.id = r.cluster_id
		 ORDER BY r.image_name`)
	return rows, err
}

// GetExposedSecrets returns all secret findings for a report.
func GetExposedSecrets(reportID int) ([]ExposedSecretRow, error) {
	var rows []ExposedSecretRow
	err := Client.Select(&rows,
		`SELECT id, report_id, severity, title, target, match
		 FROM exposed_secrets WHERE report_id = $1`,
		reportID,
	)
	return rows, err
}
