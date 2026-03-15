package db

import (
	"fmt"
	"strings"

	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

// IgnoredImageVulnerability represents a row in the ignored_image_vulnerabilities table.
type IgnoredImageVulnerability struct {
	ID         int    `db:"id" json:"id"`
	Registry   string `db:"registry" json:"registry"`
	Repository string `db:"repository" json:"repository"`
	Tag        string `db:"tag" json:"tag"`
	CVEID      string `db:"cve_id" json:"cve_id"`
	Reason     string `db:"reason" json:"reason"`
}

// InsertIgnoredImageVulnerability inserts a new ignored vulnerability.
func InsertIgnoredImageVulnerability(vuln IgnoredImageVulnerability) error {
	result, err := Client.Exec(
		`INSERT INTO ignored_image_vulnerabilities (registry, repository, tag, cve_id, reason)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT DO NOTHING`,
		vuln.Registry, vuln.Repository, vuln.Tag, vuln.CVEID, vuln.Reason,
	)
	if err != nil {
		return fmt.Errorf("failed to insert ignored image vulnerability: %w", err)
	}

	rows, _ := result.RowsAffected()
	log.Logger.Info("inserted ignored image vulnerability", "rows", rows)
	return nil
}

// BulkInsertIgnoredImageVulnerabilities inserts multiple ignored vulnerabilities in a transaction.
func BulkInsertIgnoredImageVulnerabilities(registry, repository, tag, reason string, cveIDs []string) error {
	if len(cveIDs) == 0 {
		return fmt.Errorf("no CVE IDs provided")
	}

	tx, err := Client.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Preparex(
		`INSERT INTO ignored_image_vulnerabilities (registry, repository, tag, cve_id, reason)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, cveID := range cveIDs {
		if _, err := stmt.Exec(registry, repository, tag, cveID, reason); err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				log.Logger.Debug("CVE already ignored, skipping", "cve_id", cveID)
				continue
			}
			return fmt.Errorf("failed to insert ignored vulnerability %s: %w", cveID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Logger.Info("bulk inserted ignored image vulnerabilities", "count", len(cveIDs))
	return nil
}

// GetIgnoredCVEsForImage returns a map of CVE IDs that are ignored for the given image.
func GetIgnoredCVEsForImage(registry, repository, tag string) (map[string]IgnoredImageVulnerability, error) {
	var cves []IgnoredImageVulnerability
	err := Client.Select(&cves,
		`SELECT id, registry, repository, tag, cve_id, reason
		 FROM ignored_image_vulnerabilities
		 WHERE registry = $1 AND repository = $2 AND tag = $3`,
		registry, repository, tag,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get ignores: %w", err)
	}

	ignoredCVEs := make(map[string]IgnoredImageVulnerability, len(cves))
	for _, cve := range cves {
		ignoredCVEs[cve.CVEID] = cve
	}
	return ignoredCVEs, nil
}

// DeleteIgnoredImageVulnerability removes an ignored CVE from the database.
func DeleteIgnoredImageVulnerability(registry, repository, tag, cveID string) error {
	result, err := Client.Exec(
		`DELETE FROM ignored_image_vulnerabilities
		 WHERE registry = $1 AND repository = $2 AND tag = $3 AND cve_id = $4`,
		registry, repository, tag, cveID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete ignored image vulnerability: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no ignored vulnerability found to delete")
	}

	log.Logger.Info("deleted ignored image vulnerability", "cve_id", cveID)
	return nil
}
