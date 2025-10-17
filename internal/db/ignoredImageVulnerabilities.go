package db

import (
	"database/sql"
	"fmt"

	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

// IgnoredImageVulnerability represents a row in the ignoredImageVulnerabilities table
type IgnoredImageVulnerability struct {
	ID               int    `db:"id" json:"id"`
	Registry         string `db:"registry" json:"registry"`
	Repository       string `db:"repository" json:"repository"`
	Tag              string `db:"tag" json:"tag"`
	CVEID            string `db:"cve_id" json:"cve_id"`
	Reason           string `db:"reason" json:"reason"`
	SpecificityLevel int    `db:"specificity_level" json:"specificity_level"`
}

// InsertIgnoredImageVulnerability inserts a new row into the ignoredImageVulnerabilities table
func InsertIgnoredImageVulnerability(vuln IgnoredImageVulnerability) error {
	query := `INSERT INTO ignoredImageVulnerabilities (registry, repository, tag, cve_id, reason, specificity_level) 
			  VALUES (:registry, :repository, :tag, :cve_id, :reason, :specificity_level)`

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
// that match the given registry, repository, and optionally tag
func LookupIgnoredImageVulnerabilities(registry, repository, tag string) ([]IgnoredImageVulnerability, error) {
	var query string
	var args []interface{}
	if tag == "" {
		// Lookup without tag constraint
		query = `SELECT * FROM ignoredImageVulnerabilities 
				 WHERE registry = ? AND repository = ?`
		args = []interface{}{registry, repository}
	} else {
		// Lookup with tag constraint
		query = `SELECT * FROM ignoredImageVulnerabilities 
				 WHERE registry = ? AND repository = ? AND tag = ?`
		args = []interface{}{registry, repository, tag}
	}

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

// IsCVEIgnored checks if a specific CVE is ignored for the given image
// It checks both specificity levels:
// 1. Registry + Repository (ignores CVE for all tags of this image)
// 2. Registry + Repository + Tag (ignores CVE only for this specific tag)
func IsCVEIgnored(registry, repository, tag, cveID string) (bool, error) {
	// First check for tag-specific ignore (specificity level 2)
	query := `SELECT COUNT(*) FROM ignoredImageVulnerabilities 
			  WHERE registry = ? AND repository = ? AND tag = ? AND cve_id = ? AND specificity_level = 2`

	var count int
	err := Client.Get(&count, query, registry, repository, tag, cveID)
	if err != nil {
		return false, fmt.Errorf("failed to check tag-specific ignore: %w", err)
	}

	if count > 0 {
		return true, nil
	}

	// Then check for repository-wide ignore (specificity level 1)
	query = `SELECT COUNT(*) FROM ignoredImageVulnerabilities 
			 WHERE registry = ? AND repository = ? AND cve_id = ? AND specificity_level = 1`

	err = Client.Get(&count, query, registry, repository, cveID)
	if err != nil {
		return false, fmt.Errorf("failed to check repository-wide ignore: %w", err)
	}

	return count > 0, nil
}

// GetIgnoredCVEsForImage returns a map of CVE IDs that are ignored for the given image
// The map includes both tag-specific and repository-wide ignores
func GetIgnoredCVEsForImage(registry, repository, tag string) (map[string]bool, error) {
	ignoredCVEs := make(map[string]bool)

	// Get tag-specific ignores (specificity level 2)
	query := `SELECT cve_id FROM ignoredImageVulnerabilities 
			  WHERE registry = ? AND repository = ? AND tag = ? AND specificity_level = 2`

	var cveIDs []string
	err := Client.Select(&cveIDs, query, registry, repository, tag)
	if err != nil {
		return nil, fmt.Errorf("failed to get tag-specific ignores: %w", err)
	}

	for _, cveID := range cveIDs {
		ignoredCVEs[cveID] = true
	}

	// Get repository-wide ignores (specificity level 1)
	query = `SELECT cve_id FROM ignoredImageVulnerabilities 
			 WHERE registry = ? AND repository = ? AND specificity_level = 1`

	cveIDs = []string{}
	err = Client.Select(&cveIDs, query, registry, repository)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository-wide ignores: %w", err)
	}

	for _, cveID := range cveIDs {
		ignoredCVEs[cveID] = true
	}

	log.Logger.Info("Found ignored CVEs for image", "registry", registry, "repository", repository, "tag", tag,
		"count", len(ignoredCVEs))
	return ignoredCVEs, nil
}
