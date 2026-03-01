package db

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

// Client is the sqlx database client
var Client *sqlx.DB

// Init connects to Postgres and runs schema migrations.
func Init(dsn string) error {
	dbClient, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return err
	}
	Client = dbClient

	if err := migrate(); err != nil {
		return err
	}

	return nil
}

func migrate() error {
	migrations := []struct {
		name string
		sql  string
	}{
		{"clusters", `CREATE TABLE IF NOT EXISTS clusters (
			id SERIAL PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`},
		{"images", `CREATE TABLE IF NOT EXISTS images (
			id SERIAL PRIMARY KEY,
			registry TEXT NOT NULL,
			repository TEXT NOT NULL,
			tag TEXT NOT NULL DEFAULT '',
			digest TEXT NOT NULL,
			os_family TEXT NOT NULL DEFAULT '',
			os_version TEXT NOT NULL DEFAULT '',
			os_eosl BOOLEAN NOT NULL DEFAULT FALSE,
			UNIQUE(registry, repository, digest)
		)`},
		{"image_resources", `CREATE TABLE IF NOT EXISTS image_resources (
			id SERIAL PRIMARY KEY,
			image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			resource_kind TEXT NOT NULL,
			resource_name TEXT NOT NULL,
			resource_namespace TEXT NOT NULL,
			UNIQUE(image_id, cluster_id, resource_kind, resource_name, resource_namespace)
		)`},
		{"vulnerabilities", `CREATE TABLE IF NOT EXISTS vulnerabilities (
			id SERIAL PRIMARY KEY,
			image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
			cve_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			score REAL NOT NULL DEFAULT 0,
			url TEXT NOT NULL DEFAULT '',
			resource TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL DEFAULT '',
			installed_version TEXT NOT NULL DEFAULT '',
			fixed_version TEXT NOT NULL DEFAULT '',
			UNIQUE(image_id, cve_id, resource)
		)`},
		{"config_audit_reports", `CREATE TABLE IF NOT EXISTS config_audit_reports (
			id SERIAL PRIMARY KEY,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			kind TEXT NOT NULL,
			UNIQUE(cluster_id, name, namespace, kind)
		)`},
		{"config_audit_checks", `CREATE TABLE IF NOT EXISTS config_audit_checks (
			id SERIAL PRIMARY KEY,
			report_id INTEGER NOT NULL REFERENCES config_audit_reports(id) ON DELETE CASCADE,
			check_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT ''
		)`},
		{"cluster_infra_audit_reports", `CREATE TABLE IF NOT EXISTS cluster_infra_audit_reports (
			id SERIAL PRIMARY KEY,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			UNIQUE(cluster_id, name, kind)
		)`},
		{"cluster_infra_audit_checks", `CREATE TABLE IF NOT EXISTS cluster_infra_audit_checks (
			id SERIAL PRIMARY KEY,
			report_id INTEGER NOT NULL REFERENCES cluster_infra_audit_reports(id) ON DELETE CASCADE,
			check_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT ''
		)`},
		{"rbac_assessment_reports", `CREATE TABLE IF NOT EXISTS rbac_assessment_reports (
			id SERIAL PRIMARY KEY,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			kind TEXT NOT NULL,
			UNIQUE(cluster_id, name, namespace, kind)
		)`},
		{"rbac_assessment_checks", `CREATE TABLE IF NOT EXISTS rbac_assessment_checks (
			id SERIAL PRIMARY KEY,
			report_id INTEGER NOT NULL REFERENCES rbac_assessment_reports(id) ON DELETE CASCADE,
			check_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT ''
		)`},
		{"cluster_rbac_assessment_reports", `CREATE TABLE IF NOT EXISTS cluster_rbac_assessment_reports (
			id SERIAL PRIMARY KEY,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			UNIQUE(cluster_id, name, kind)
		)`},
		{"cluster_rbac_assessment_checks", `CREATE TABLE IF NOT EXISTS cluster_rbac_assessment_checks (
			id SERIAL PRIMARY KEY,
			report_id INTEGER NOT NULL REFERENCES cluster_rbac_assessment_reports(id) ON DELETE CASCADE,
			check_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT ''
		)`},
		{"exposed_secret_reports", `CREATE TABLE IF NOT EXISTS exposed_secret_reports (
			id SERIAL PRIMARY KEY,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			image_name TEXT NOT NULL,
			image_digest TEXT NOT NULL,
			resource_kind TEXT NOT NULL,
			resource_name TEXT NOT NULL,
			resource_namespace TEXT NOT NULL,
			UNIQUE(cluster_id, image_name, image_digest, resource_kind, resource_name, resource_namespace)
		)`},
		{"exposed_secrets", `CREATE TABLE IF NOT EXISTS exposed_secrets (
			id SERIAL PRIMARY KEY,
			report_id INTEGER NOT NULL REFERENCES exposed_secret_reports(id) ON DELETE CASCADE,
			severity TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			match TEXT NOT NULL DEFAULT ''
		)`},
		{"compliance_reports", `CREATE TABLE IF NOT EXISTS compliance_reports (
			id SERIAL PRIMARY KEY,
			cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
			report_id TEXT NOT NULL,
			title TEXT NOT NULL,
			fail_count INTEGER NOT NULL DEFAULT 0,
			pass_count INTEGER NOT NULL DEFAULT 0,
			UNIQUE(cluster_id, report_id)
		)`},
		{"compliance_checks", `CREATE TABLE IF NOT EXISTS compliance_checks (
			id SERIAL PRIMARY KEY,
			report_id INTEGER NOT NULL REFERENCES compliance_reports(id) ON DELETE CASCADE,
			check_id TEXT NOT NULL,
			check_ids JSONB NOT NULL DEFAULT '[]',
			name TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL,
			total_failed INTEGER
		)`},
		{"ignored_image_vulnerabilities", `CREATE TABLE IF NOT EXISTS ignored_image_vulnerabilities (
			id SERIAL PRIMARY KEY,
			registry TEXT NOT NULL,
			repository TEXT NOT NULL,
			tag TEXT NOT NULL,
			cve_id TEXT NOT NULL,
			reason TEXT,
			UNIQUE(registry, repository, tag, cve_id)
		)`},
	}

	for _, m := range migrations {
		if _, err := Client.Exec(m.sql); err != nil {
			return err
		}
		log.Logger.Debug("migration OK", "table", m.name)
	}

	log.Logger.Info("database migrations complete")
	return nil
}
