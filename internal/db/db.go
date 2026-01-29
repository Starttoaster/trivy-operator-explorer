package db

import (
	"fmt"
	"strings"

	"github.com/chia-network/go-modules/pkg/slogs"
	"github.com/jmoiron/sqlx"
	// driver for sqlite3
	_ "github.com/mattn/go-sqlite3"
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

	err = initImageVulnerabilityCountTimeseriesTable()
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

	slogs.Logr.Info("✓ ignoredImageVulnerabilities table created/verified")
	return nil
}

func initImageVulnerabilityCountTimeseriesTable() error {
	_, err := Client.Exec(`CREATE TABLE IF NOT EXISTS imageVulnerabilityCountTimeseries (
		id INTEGER PRIMARY KEY,
		time TEXT NOT NULL,
		critical INTEGER,
		high INTEGER,
		medium INTEGER,
		low INTEGER,
		unknown INTEGER
	);`)
	if err != nil {
		return err
	}

	_, err = Client.Exec(`CREATE INDEX IF NOT EXISTS idx_imageVulnerabilityCountTimeseries_time ON imageVulnerabilityCountTimeseries(time)`)
	if err != nil {
		return err
	}

	slogs.Logr.Info("✓ imageVulnerabilityCountTimeseries table created/verified")
	return nil
}
