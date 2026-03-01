package agent

import (
	"time"

	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/models"
)

// WatcherConfig holds the configuration for the watcher.
type WatcherConfig struct {
	ClusterName  string
	SyncInterval time.Duration
	Client       *Client
}

// Watcher periodically polls K8s CRDs and syncs to the central API.
type Watcher struct {
	cfg WatcherConfig
}

// NewWatcher creates a new Watcher.
func NewWatcher(cfg WatcherConfig) *Watcher {
	return &Watcher{cfg: cfg}
}

// Run starts the polling loop. It blocks forever.
func (w *Watcher) Run() {
	log.Logger.Info("starting agent watcher",
		"cluster", w.cfg.ClusterName,
		"interval", w.cfg.SyncInterval.String(),
	)

	w.syncOnce()

	ticker := time.NewTicker(w.cfg.SyncInterval)
	defer ticker.Stop()

	for range ticker.C {
		w.syncOnce()
	}
}

func (w *Watcher) syncOnce() {
	log.Logger.Info("starting sync", "cluster", w.cfg.ClusterName)

	report := models.ClusterReport{
		ClusterName: w.cfg.ClusterName,
	}

	vulns, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error listing vulnerability reports", "error", err.Error())
	} else {
		report.Vulnerabilities = NormalizeVulnerabilityReports(vulns)
	}

	configAudits, err := kube.GetConfigAuditReportList()
	if err != nil {
		log.Logger.Error("error listing config audit reports", "error", err.Error())
	} else {
		report.ConfigAudits = NormalizeConfigAuditReports(configAudits)
	}

	clusterInfra, err := kube.GetClusterInfraAssessmentReportList()
	if err != nil {
		log.Logger.Error("error listing cluster infra assessment reports", "error", err.Error())
	} else {
		report.ClusterInfraAudits = NormalizeClusterInfraAuditReports(clusterInfra)
	}

	rbac, err := kube.GetRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error listing rbac assessment reports", "error", err.Error())
	} else {
		report.RbacAssessments = NormalizeRbacAssessmentReports(rbac)
	}

	clusterRbac, err := kube.GetClusterRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error listing cluster rbac assessment reports", "error", err.Error())
	} else {
		report.ClusterRbacAssessments = NormalizeClusterRbacAssessmentReports(clusterRbac)
	}

	secrets, err := kube.GetExposedSecretReportList()
	if err != nil {
		log.Logger.Error("error listing exposed secret reports", "error", err.Error())
	} else {
		report.ExposedSecrets = NormalizeExposedSecretReports(secrets)
	}

	compliance, err := kube.GetComplianceReportList()
	if err != nil {
		log.Logger.Error("error listing compliance reports", "error", err.Error())
	} else {
		report.ComplianceReports = NormalizeComplianceReports(compliance)
	}

	if err := w.cfg.Client.Sync(report); err != nil {
		log.Logger.Error("sync failed", "cluster", w.cfg.ClusterName, "error", err.Error())
		return
	}

	log.Logger.Info("sync complete", "cluster", w.cfg.ClusterName)
}
