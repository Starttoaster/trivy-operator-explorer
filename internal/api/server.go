package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/models"
)

// ServerConfig holds the configuration for the API server.
type ServerConfig struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	CAFile     string
}

// Start starts the mTLS API server.
func Start(cfg ServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sync", syncHandler)
	mux.HandleFunc("/api/v1/healthz", healthzHandler)

	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" {
		return fmt.Errorf("TLS not fully configured: cert-file, key-file, and ca-file are all required")
	}

	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return fmt.Errorf("reading CA file: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	server := &http.Server{
		Addr:      cfg.ListenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Logger.Info("API server listening with mTLS", "addr", cfg.ListenAddr)
	return server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
}

func syncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var report models.ClusterReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		log.Logger.Error("failed to decode sync request", "error", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if report.ClusterName == "" {
		http.Error(w, "cluster_name is required", http.StatusBadRequest)
		return
	}

	if err := db.SyncClusterReport(report); err != nil {
		log.Logger.Error("failed to sync cluster report", "cluster", report.ClusterName, "error", err)
		http.Error(w, "sync failed", http.StatusInternalServerError)
		return
	}

	log.Logger.Info("synced cluster report",
		"cluster", report.ClusterName,
		"vulns", len(report.Vulnerabilities),
		"config_audits", len(report.ConfigAudits),
		"cluster_infra_audits", len(report.ClusterInfraAudits),
		"rbac", len(report.RbacAssessments),
		"cluster_rbac", len(report.ClusterRbacAssessments),
		"exposed_secrets", len(report.ExposedSecrets),
		"compliance", len(report.ComplianceReports),
	)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
