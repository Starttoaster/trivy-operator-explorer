package db

import (
	"github.com/jmoiron/sqlx"
)

// VulnerabilityRow represents a row in the vulnerabilities table.
type VulnerabilityRow struct {
	ID               int     `db:"id"`
	ImageID          int     `db:"image_id"`
	CVEID            string  `db:"cve_id"`
	Severity         string  `db:"severity"`
	Score            float64 `db:"score"`
	URL              string  `db:"url"`
	Resource         string  `db:"resource"`
	Title            string  `db:"title"`
	InstalledVersion string  `db:"installed_version"`
	FixedVersion     string  `db:"fixed_version"`
}

// UpsertVulnerability inserts or updates a vulnerability for an image.
func UpsertVulnerability(tx *sqlx.Tx, imageID int, cveID, severity string, score float64, url, resource, title, installedVersion, fixedVersion string) error {
	_, err := tx.Exec(
		`INSERT INTO vulnerabilities (image_id, cve_id, severity, score, url, resource, title, installed_version, fixed_version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (image_id, cve_id, resource) DO UPDATE
		   SET severity = $3, score = $4, url = $5, title = $7, installed_version = $8, fixed_version = $9`,
		imageID, cveID, severity, score, url, resource, title, installedVersion, fixedVersion,
	)
	return err
}

// DeleteVulnerabilitiesByImageID removes all vulnerabilities for an image.
func DeleteVulnerabilitiesByImageID(tx *sqlx.Tx, imageID int) error {
	_, err := tx.Exec(`DELETE FROM vulnerabilities WHERE image_id = $1`, imageID)
	return err
}

// GetVulnerabilitiesForImage returns all vulnerability rows for an image.
func GetVulnerabilitiesForImage(imageID int) ([]VulnerabilityRow, error) {
	var rows []VulnerabilityRow
	err := Client.Select(&rows,
		`SELECT id, image_id, cve_id, severity, score, url, resource, title, installed_version, fixed_version
		 FROM vulnerabilities WHERE image_id = $1
		 ORDER BY score DESC`,
		imageID,
	)
	return rows, err
}

// VulnerabilityWithImage is a vulnerability row joined with image info.
type VulnerabilityWithImage struct {
	VulnerabilityRow
	Registry   string `db:"registry"`
	Repository string `db:"repository"`
	Tag        string `db:"tag"`
	Digest     string `db:"digest"`
}

// GetAllVulnerabilitySummary returns a summary of vulnerability counts per image.
func GetAllVulnerabilitySummary() ([]VulnerabilityRow, error) {
	var rows []VulnerabilityRow
	err := Client.Select(&rows,
		`SELECT id, image_id, cve_id, severity, score, url, resource, title, installed_version, fixed_version
		 FROM vulnerabilities ORDER BY image_id, score DESC`)
	return rows, err
}
