package db

import (
	"fmt"
	"strings"

	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

// IgnoredImageVulnerability represents a row in the ignoredImageVulnerabilities table
type IgnoredImageVulnerability struct {
	ID         int    `db:"id" json:"id"`
	Registry   string `db:"registry" json:"registry"`
	Repository string `db:"repository" json:"repository"`
	Tag        string `db:"tag" json:"tag"`
	CVEID      string `db:"cve_id" json:"cve_id"`
	Reason     string `db:"reason" json:"reason"`
}

// InsertIgnoredImageVulnerability inserts a new row into the ignoredImageVulnerabilities table
func InsertIgnoredImageVulnerability(vuln IgnoredImageVulnerability) error {
	query := `INSERT INTO ignoredImageVulnerabilities (registry, repository, tag, cve_id, reason) 
			  VALUES (:registry, :repository, :tag, :cve_id, :reason)`

	result, err := Client.NamedExec(query, vuln)
	if err != nil {
		return fmt.Errorf("failed to insert ignored image vulnerability: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID: %w", err)
	}

	log.Logger.Info("Successfully inserted ignored image vulnerability", "id", id)
	return nil
}

// BulkInsertIgnoredImageVulnerabilities inserts multiple ignored vulnerabilities in a transaction
func BulkInsertIgnoredImageVulnerabilities(registry, repository, tag, reason string, cveIDs []string) error {
	if len(cveIDs) == 0 {
		return fmt.Errorf("no CVE IDs provided")
	}

	// Start a transaction
	tx, err := Client.Beginx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			// Do nothing, this happens commonly when the transaction has already been committed
		}
	}()

	query := `INSERT INTO ignoredImageVulnerabilities (registry, repository, tag, cve_id, reason) 
			  VALUES (?, ?, ?, ?, ?)`

	stmt, err := tx.Preparex(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Logger.Error("Failed to close statement", "error", err)
		}
	}()

	// Insert each CVE
	for _, cveID := range cveIDs {
		_, err := stmt.Exec(registry, repository, tag, cveID, reason)
		if err != nil {
			// If it's a unique constraint violation, log and continue (idempotent)
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				log.Logger.Debug("CVE already ignored, skipping", "cve_id", cveID, "registry", registry, "repository", repository, "tag", tag)
				continue
			}
			return fmt.Errorf("failed to insert ignored vulnerability %s: %w", cveID, err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Logger.Info("Successfully bulk inserted ignored image vulnerabilities", "count", len(cveIDs), "registry", registry, "repository", repository, "tag", tag)
	return nil
}

// GetIgnoredCVEsForImage returns a map of CVE IDs that are ignored for the given image
func GetIgnoredCVEsForImage(registry, repository, tag string) (map[string]IgnoredImageVulnerability, error) {
	query := `SELECT cve_id, reason FROM ignoredImageVulnerabilities 
			  WHERE registry = ? AND repository = ? AND tag = ?`

	var cves []IgnoredImageVulnerability
	err := Client.Select(&cves, query, registry, repository, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to get ignores: %w", err)
	}

	ignoredCVEs := make(map[string]IgnoredImageVulnerability)
	for _, cve := range cves {
		ignoredCVEs[cve.CVEID] = cve
	}

	log.Logger.Debug("Found ignored CVEs for image", "registry", registry, "repository", repository, "tag", tag,
		"count", len(ignoredCVEs))
	return ignoredCVEs, nil
}

// DeleteIgnoredImageVulnerability removes an ignored CVE from the database
func DeleteIgnoredImageVulnerability(registry, repository, tag, cveID string) error {
	query := `DELETE FROM ignoredImageVulnerabilities 
			  WHERE registry = ? AND repository = ? AND tag = ? AND cve_id = ?`

	result, err := Client.Exec(query, registry, repository, tag, cveID)
	if err != nil {
		return fmt.Errorf("failed to delete ignored image vulnerability: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no ignored vulnerability found to delete")
	}

	log.Logger.Info("Successfully deleted ignored image vulnerability", "registry", registry, "repository", repository, "tag", tag, "cve_id", cveID)
	return nil
}
