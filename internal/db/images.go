package db

import (
	"github.com/jmoiron/sqlx"
)

// ImageRow represents a row in the images table.
type ImageRow struct {
	ID         int    `db:"id"`
	Registry   string `db:"registry"`
	Repository string `db:"repository"`
	Tag        string `db:"tag"`
	Digest     string `db:"digest"`
	OSFamily   string `db:"os_family"`
	OSVersion  string `db:"os_version"`
	OSEOSL     bool   `db:"os_eosl"`
}

// ImageResourceRow represents a row in the image_resources table.
type ImageResourceRow struct {
	ID                int    `db:"id"`
	ImageID           int    `db:"image_id"`
	ClusterID         int    `db:"cluster_id"`
	ResourceKind      string `db:"resource_kind"`
	ResourceName      string `db:"resource_name"`
	ResourceNamespace string `db:"resource_namespace"`
}

// UpsertImage inserts or updates an image and returns its ID.
func UpsertImage(tx *sqlx.Tx, registry, repository, tag, digest, osFamily, osVersion string, osEOSL bool) (int, error) {
	var id int
	err := tx.QueryRow(
		`INSERT INTO images (registry, repository, tag, digest, os_family, os_version, os_eosl)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (registry, repository, digest) DO UPDATE
		   SET tag = $3, os_family = $5, os_version = $6, os_eosl = $7
		 RETURNING id`,
		registry, repository, tag, digest, osFamily, osVersion, osEOSL,
	).Scan(&id)
	return id, err
}

// InsertImageResource inserts an image-to-cluster-resource mapping.
func InsertImageResource(tx *sqlx.Tx, imageID, clusterID int, kind, name, namespace string) error {
	_, err := tx.Exec(
		`INSERT INTO image_resources (image_id, cluster_id, resource_kind, resource_name, resource_namespace)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT DO NOTHING`,
		imageID, clusterID, kind, name, namespace,
	)
	return err
}

// DeleteImageResourcesByCluster removes all image_resources for a cluster.
func DeleteImageResourcesByCluster(tx *sqlx.Tx, clusterID int) error {
	_, err := tx.Exec(`DELETE FROM image_resources WHERE cluster_id = $1`, clusterID)
	return err
}

// ImageWithResources is a joined view of an image and one of its resource rows.
type ImageWithResources struct {
	ImageRow
	ClusterName       string `db:"cluster_name"`
	ResourceKind      string `db:"resource_kind"`
	ResourceName      string `db:"resource_name"`
	ResourceNamespace string `db:"resource_namespace"`
}

// GetAllImagesWithResources returns all images joined with their cluster/resource info.
func GetAllImagesWithResources() ([]ImageWithResources, error) {
	var rows []ImageWithResources
	err := Client.Select(&rows,
		`SELECT i.id, i.registry, i.repository, i.tag, i.digest,
		        i.os_family, i.os_version, i.os_eosl,
		        c.name AS cluster_name,
		        ir.resource_kind, ir.resource_name, ir.resource_namespace
		 FROM images i
		 JOIN image_resources ir ON ir.image_id = i.id
		 JOIN clusters c ON c.id = ir.cluster_id
		 ORDER BY i.repository, i.tag`)
	return rows, err
}

// GetImageByRegistryRepoDigest looks up a single image.
func GetImageByRegistryRepoDigest(registry, repository, digest string) (*ImageRow, error) {
	var img ImageRow
	err := Client.Get(&img,
		`SELECT id, registry, repository, tag, digest, os_family, os_version, os_eosl
		 FROM images WHERE registry = $1 AND repository = $2 AND digest = $3`,
		registry, repository, digest,
	)
	if err != nil {
		return nil, err
	}
	return &img, nil
}

// GetResourcesForImage returns all cluster/resource mappings for an image.
func GetResourcesForImage(imageID int) ([]ImageWithResources, error) {
	var rows []ImageWithResources
	err := Client.Select(&rows,
		`SELECT i.id, i.registry, i.repository, i.tag, i.digest,
		        i.os_family, i.os_version, i.os_eosl,
		        c.name AS cluster_name,
		        ir.resource_kind, ir.resource_name, ir.resource_namespace
		 FROM images i
		 JOIN image_resources ir ON ir.image_id = i.id
		 JOIN clusters c ON c.id = ir.cluster_id
		 WHERE i.id = $1`,
		imageID,
	)
	return rows, err
}
