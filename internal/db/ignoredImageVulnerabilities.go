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

// BulkInsertIgnoredImageVulnerabilities inserts multiple ignored vulnerabilities in
// a single transaction. Returns the number of rows actually inserted (rows skipped
// due to UNIQUE constraint violations are not counted, making the call idempotent).
func BulkInsertIgnoredImageVulnerabilities(registry, repository, tag, reason string, cveIDs []string) (int64, error) {
	if len(cveIDs) == 0 {
		return 0, fmt.Errorf("no CVE IDs provided")
	}

	tx, err := Client.Beginx()
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
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
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Logger.Error("Failed to close statement", "error", err)
		}
	}()

	var inserted int64
	for _, cveID := range cveIDs {
		_, err := stmt.Exec(registry, repository, tag, cveID, reason)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				log.Logger.Debug("CVE already ignored, skipping", "cve_id", cveID, "registry", registry, "repository", repository, "tag", tag)
				continue
			}
			return inserted, fmt.Errorf("failed to insert ignored vulnerability %s: %w", cveID, err)
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Logger.Info("Successfully bulk inserted ignored image vulnerabilities", "inserted", inserted, "requested", len(cveIDs), "registry", registry, "repository", repository, "tag", tag)
	return inserted, nil
}

// IgnoredImageVulnerabilityFilter optionally narrows a ListIgnoredImageVulnerabilities query.
// Empty fields are ignored (i.e. match anything).
type IgnoredImageVulnerabilityFilter struct {
	Registry   string
	Repository string
	Tag        string
}

// ListIgnoredImageVulnerabilities returns all ignored image vulnerabilities, optionally
// filtered by registry/repository/tag. The result is sorted by registry, repository, tag, cve_id.
func ListIgnoredImageVulnerabilities(f IgnoredImageVulnerabilityFilter) ([]IgnoredImageVulnerability, error) {
	query := `SELECT id, registry, repository, tag, cve_id, reason FROM ignoredImageVulnerabilities`
	var (
		conds []string
		args  []interface{}
	)
	if f.Registry != "" {
		conds = append(conds, "registry = ?")
		args = append(args, f.Registry)
	}
	if f.Repository != "" {
		conds = append(conds, "repository = ?")
		args = append(args, f.Repository)
	}
	if f.Tag != "" {
		conds = append(conds, "tag = ?")
		args = append(args, f.Tag)
	}
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY registry, repository, tag, cve_id"

	var rows []IgnoredImageVulnerability
	if err := Client.Select(&rows, query, args...); err != nil {
		return nil, fmt.Errorf("failed to list ignored image vulnerabilities: %w", err)
	}
	return rows, nil
}

// BulkDeleteIgnoredImageVulnerabilities removes multiple ignored CVEs for a single
// image in a single transaction. Returns the number of rows actually deleted; rows
// that don't exist are silently ignored, making the call idempotent.
func BulkDeleteIgnoredImageVulnerabilities(registry, repository, tag string, cveIDs []string) (int64, error) {
	if len(cveIDs) == 0 {
		return 0, fmt.Errorf("no CVE IDs provided")
	}

	tx, err := Client.Beginx()
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			// Do nothing, this happens commonly when the transaction has already been committed
		}
	}()

	query := `DELETE FROM ignoredImageVulnerabilities 
			  WHERE registry = ? AND repository = ? AND tag = ? AND cve_id = ?`

	stmt, err := tx.Preparex(query)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Logger.Error("Failed to close statement", "error", err)
		}
	}()

	var deleted int64
	for _, cveID := range cveIDs {
		res, err := stmt.Exec(registry, repository, tag, cveID)
		if err != nil {
			return deleted, fmt.Errorf("failed to delete ignored vulnerability %s: %w", cveID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return deleted, fmt.Errorf("failed to read rows affected: %w", err)
		}
		deleted += n
	}

	if err := tx.Commit(); err != nil {
		return deleted, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Logger.Info("Successfully bulk deleted ignored image vulnerabilities", "deleted", deleted, "requested", len(cveIDs), "registry", registry, "repository", repository, "tag", tag)
	return deleted, nil
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
