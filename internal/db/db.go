package db

import (
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

// Client is the sqlx database client
var Client *sqlx.DB

func Init(path string) error {
	dbPathNoTrailingSlash := strings.TrimSuffix(path, "/")
	dbClient, err := sqlx.Connect("sqlite3", fmt.Sprintf("%s/trivy-explorer.sqlite", dbPathNoTrailingSlash))
	if err != nil {
		return err
	}
	Client = dbClient

	err = initImagesTable()
	if err != nil {
		return err
	}

	err = initImagesResourcesTable()
	if err != nil {
		return err
	}

	err = initImageResourceJunctionTable()
	if err != nil {
		return err
	}

	return nil
}

func initImagesTable() error {
	_, err := Client.Exec(`CREATE TABLE IF NOT EXISTS images (
		id INTEGER PRIMARY KEY,
		registry TEXT NOT NULL,
		repository TEXT NOT NULL,
		tag TEXT NOT NULL,
		sha TEXT NOT NULL,
		os TEXT,
		eosl BOOLEAN,
		UNIQUE(registry, repository, tag, sha)
	);`)
	if err != nil {
		return err
	}

	log.Logger.Info("✓ images table created/verified")
	return nil
}

func initImagesResourcesTable() error {
	_, err := Client.Exec(`CREATE TABLE IF NOT EXISTS images_resources (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		namespace TEXT NOT NULL,
		kind TEXT NOT NULL,
		UNIQUE(name, namespace, kind)
	);`)
	if err != nil {
		return err
	}

	log.Logger.Info("✓ images_resources table created/verified")
	return nil
}

func initImageResourceJunctionTable() error {
	_, err := Client.Exec(`CREATE TABLE IF NOT EXISTS images_resources_relations (
        id INTEGER PRIMARY KEY,
        image_id INTEGER NOT NULL,
        resource_id INTEGER NOT NULL,
        FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE,
        FOREIGN KEY (resource_id) REFERENCES images_resources(id) ON DELETE CASCADE,
        UNIQUE(image_id, resource_id)
    );`)
	if err != nil {
		return err
	}

	log.Logger.Info("✓ images_resources_relations table created/verified")
	return nil
}
