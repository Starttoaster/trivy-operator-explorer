package db

import (
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	// driver for sqlite3
	_ "github.com/mattn/go-sqlite3"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

// Client is the sqlx database client
var Client *sqlx.DB

// Init inits the database client and ensures some initial database state
func Init(path string) error {
	dbPathNoTrailingSlash := strings.TrimSuffix(path, "/")
	dbClient, err := sqlx.Connect("sqlite3", fmt.Sprintf("%s/trivy-explorer.sqlite", dbPathNoTrailingSlash))
	if err != nil {
		return err
	}
	Client = dbClient

	err = initIgnoredImageVulnerabilitiesTable()
	if err != nil {
		return err
	}

	return nil
}

func initIgnoredImageVulnerabilitiesTable() error {
	_, err := Client.Exec(`CREATE TABLE IF NOT EXISTS ignoredImageVulnerabilities (
		id INTEGER PRIMARY KEY,
		registry TEXT NOT NULL,
		repository TEXT NOT NULL,
		tag TEXT NOT NULL,
		cve_id TEXT NOT NULL,
		reason TEXT,
		UNIQUE(registry, repository, tag, cve_id)
	);`)
	if err != nil {
		return err
	}

	log.Logger.Info("✓ ignoredImageVulnerabilities table created/verified")
	return nil
}
