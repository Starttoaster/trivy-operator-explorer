package db

import "time"

// UpsertCluster creates or updates a cluster record and returns its ID.
func UpsertCluster(name string) (int, error) {
	var id int
	err := Client.QueryRow(
		`INSERT INTO clusters (name, last_heartbeat)
		 VALUES ($1, $2)
		 ON CONFLICT (name) DO UPDATE SET last_heartbeat = $2
		 RETURNING id`,
		name, time.Now(),
	).Scan(&id)
	return id, err
}

// ClusterRow represents a row in the clusters table.
type ClusterRow struct {
	ID            int       `db:"id"`
	Name          string    `db:"name"`
	LastHeartbeat time.Time `db:"last_heartbeat"`
}

// GetClusters returns all known clusters.
func GetClusters() ([]ClusterRow, error) {
	var clusters []ClusterRow
	err := Client.Select(&clusters, `SELECT id, name, last_heartbeat FROM clusters ORDER BY name`)
	return clusters, err
}
