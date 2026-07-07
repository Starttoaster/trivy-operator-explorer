// Package collect implements the collector's sync loop: read every
// trivy-operator report type (plus running-pod/container data) from the local
// cluster and write a bundle into S3 under the configured cluster name.
package collect

import (
	"context"
	"time"

	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/store"
	"github.com/starttoaster/trivy-operator-explorer/internal/version"
)

// Run performs an initial sync and then re-syncs every interval until the
// context is cancelled.
func Run(ctx context.Context, st *store.Client, cluster string, interval time.Duration) {
	syncOnce(ctx, st, cluster)

	if interval <= 0 {
		log.Logger.Warn("collector: non-positive sync interval, running a single sync then idling", "interval", interval.String())
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce(ctx, st, cluster)
		}
	}
}

// syncOnce gathers a full bundle and writes it to S3. If any report type fails
// to read, the whole cycle is skipped so we never overwrite a previously-good
// bundle with a partial one (keeping last-good data on transient errors).
func syncOnce(ctx context.Context, st *store.Client, cluster string) {
	b := &store.Bundle{}
	var gatherErr error

	if v, err := kube.GetVulnerabilityReportList(); err != nil {
		log.Logger.Error("collector: error getting VulnerabilityReports", "error", err.Error())
		gatherErr = err
	} else {
		b.VulnerabilityReports = v
	}

	if v, err := kube.GetComplianceReportList(); err != nil {
		log.Logger.Error("collector: error getting ComplianceReports", "error", err.Error())
		gatherErr = err
	} else {
		b.ComplianceReports = v
	}

	if v, err := kube.GetRbacAssessmentReportList(); err != nil {
		log.Logger.Error("collector: error getting RbacAssessmentReports", "error", err.Error())
		gatherErr = err
	} else {
		b.RbacAssessmentReports = v
	}

	if v, err := kube.GetClusterRbacAssessmentReportList(); err != nil {
		log.Logger.Error("collector: error getting ClusterRbacAssessmentReports", "error", err.Error())
		gatherErr = err
	} else {
		b.ClusterRbacAssessmentReports = v
	}

	if v, err := kube.GetConfigAuditReportList(); err != nil {
		log.Logger.Error("collector: error getting ConfigAuditReports", "error", err.Error())
		gatherErr = err
	} else {
		b.ConfigAuditReports = v
	}

	if v, err := kube.GetClusterInfraAssessmentReportList(); err != nil {
		log.Logger.Error("collector: error getting ClusterInfraAssessmentReports", "error", err.Error())
		gatherErr = err
	} else {
		b.ClusterInfraAssessmentReports = v
	}

	if v, err := kube.GetExposedSecretReportList(); err != nil {
		log.Logger.Error("collector: error getting ExposedSecretReports", "error", err.Error())
		gatherErr = err
	} else {
		b.ExposedSecretReports = v
	}

	if v, err := kube.GetContainerImagesMap(); err != nil {
		log.Logger.Error("collector: error getting container images", "error", err.Error())
		gatherErr = err
	} else {
		b.ContainerImages = v
	}

	if gatherErr != nil {
		log.Logger.Error("collector: skipping S3 write due to gather error; keeping last-good data", "cluster", cluster)
		return
	}

	if err := st.WriteBundle(ctx, cluster, b, version.Version); err != nil {
		log.Logger.Error("collector: error writing bundle to S3", "cluster", cluster, "error", err.Error())
		return
	}

	log.Logger.Info("collector: synced cluster reports to S3",
		"cluster", cluster,
		"vulnerabilityReports", len(b.VulnerabilityReports.Items),
		"complianceReports", len(b.ComplianceReports.Items),
		"rbacAssessmentReports", len(b.RbacAssessmentReports.Items),
		"clusterRbacAssessmentReports", len(b.ClusterRbacAssessmentReports.Items),
		"configAuditReports", len(b.ConfigAuditReports.Items),
		"clusterInfraAssessmentReports", len(b.ClusterInfraAssessmentReports.Items),
		"exposedSecretReports", len(b.ExposedSecretReports.Items),
		"containerImages", len(b.ContainerImages),
	)
}
