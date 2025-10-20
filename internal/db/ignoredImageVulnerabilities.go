package db

import (
	"database/sql"
	"fmt"

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

// LookupIgnoredImageVulnerabilities finds rows in the ignoredImageVulnerabilities table
// that match the given registry, repository, and tag
func LookupIgnoredImageVulnerabilities(registry, repository, tag string) ([]IgnoredImageVulnerability, error) {
	var query string
	var args []interface{}
	query = `SELECT * FROM ignoredImageVulnerabilities 
				 WHERE registry = ? AND repository = ? AND tag = ?`
	args = []interface{}{registry, repository, tag}

	var vulnerabilities []IgnoredImageVulnerability
	err := Client.Select(&vulnerabilities, query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return []IgnoredImageVulnerability{}, nil
		}
		return nil, err
	}

	log.Logger.Info("Found ignored image vulnerabilities", "registry", registry, "repository", repository, "tag", tag,
		"count", len(vulnerabilities))
	return vulnerabilities, nil
}

// GetIgnoredCVEsForImage returns a map of CVE IDs that are ignored for the given image
func GetIgnoredCVEsForImage(registry, repository, tag string) (map[string]bool, error) {
	ignoredCVEs := make(map[string]bool)
	query := `SELECT cve_id FROM ignoredImageVulnerabilities 
			  WHERE registry = ? AND repository = ? AND tag = ?`

	var cveIDs []string
	err := Client.Select(&cveIDs, query, registry, repository, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to get ignores: %w", err)
	}

	for _, cveID := range cveIDs {
		ignoredCVEs[cveID] = true
	}

	log.Logger.Info("Found ignored CVEs for image", "registry", registry, "repository", repository, "tag", tag,
		"count", len(ignoredCVEs))
	return ignoredCVEs, nil
}
