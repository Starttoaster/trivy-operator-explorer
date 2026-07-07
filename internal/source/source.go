// Package source is the frontend's read side. It maintains an in-memory cache
// of every cluster's report bundle (loaded from S3 via internal/store) and
// exposes cluster-aware getters that mirror the surface the web/API/MCP layers
// previously called directly on internal/kube.
//
// A cluster argument of "" means "all clusters": the getters concatenate the
// items from every cached bundle. Each item is stamped with the cluster it came
// from (via utils.ClusterLabel) at load time so views can attribute rows.
package source

import (
	"context"
	"sync"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/store"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
)

// provider is the package-level singleton, mirroring the global-client pattern
// used by internal/kube and internal/db.
var provider *Provider

// Provider caches cluster bundles and refreshes them on an interval.
type Provider struct {
	store    *store.Client
	interval time.Duration

	mu       sync.RWMutex
	clusters []string
	bundles  map[string]*store.Bundle
}

// Init constructs the package-level provider, performs an initial synchronous
// refresh so the first requests have data, and starts the background refresh
// loop.
func Init(st *store.Client, interval time.Duration) error {
	provider = &Provider{
		store:    st,
		interval: interval,
		bundles:  map[string]*store.Bundle{},
	}
	provider.refresh()
	go provider.loop()
	return nil
}

func (p *Provider) loop() {
	if p.interval <= 0 {
		return
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for range ticker.C {
		p.refresh()
	}
}

// refresh reloads every cluster bundle from S3 and atomically swaps the cache.
func (p *Provider) refresh() {
	ctx := context.Background()

	clusters, err := p.store.ListClusters(ctx)
	if err != nil {
		log.Logger.Error("source: error listing clusters", "error", err.Error())
		return
	}

	bundles := make(map[string]*store.Bundle, len(clusters))
	for _, cluster := range clusters {
		b, err := p.store.LoadCluster(ctx, cluster)
		if err != nil {
			log.Logger.Error("source: error loading cluster bundle", "cluster", cluster, "error", err.Error())
			continue
		}
		stampCluster(b, cluster)
		bundles[cluster] = b
	}

	p.mu.Lock()
	p.clusters = clusters
	p.bundles = bundles
	p.mu.Unlock()

	log.Logger.Debug("source: refreshed cluster cache", "clusters", len(bundles))
}

// ListClusters returns the currently-cached cluster names.
func ListClusters() []string {
	if provider == nil {
		return nil
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	out := make([]string, len(provider.clusters))
	copy(out, provider.clusters)
	return out
}

// bundlesFor returns the bundles matching the cluster selector. An empty
// cluster returns every bundle (aggregate mode).
func bundlesFor(cluster string) []*store.Bundle {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if cluster != "" {
		if b, ok := provider.bundles[cluster]; ok {
			return []*store.Bundle{b}
		}
		return nil
	}
	out := make([]*store.Bundle, 0, len(provider.bundles))
	for _, b := range provider.bundles {
		out = append(out, b)
	}
	return out
}

// GetVulnerabilityReportList returns the merged vulnerability reports for the
// selected cluster (or all clusters when cluster == "").
func GetVulnerabilityReportList(cluster string) (*v1alpha1.VulnerabilityReportList, error) {
	out := &v1alpha1.VulnerabilityReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.VulnerabilityReports != nil {
			out.Items = append(out.Items, b.VulnerabilityReports.Items...)
		}
	}
	return out, nil
}

// GetComplianceReportList returns the merged cluster compliance reports.
func GetComplianceReportList(cluster string) (*v1alpha1.ClusterComplianceReportList, error) {
	out := &v1alpha1.ClusterComplianceReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.ComplianceReports != nil {
			out.Items = append(out.Items, b.ComplianceReports.Items...)
		}
	}
	return out, nil
}

// GetRbacAssessmentReportList returns the merged rbac assessment reports.
func GetRbacAssessmentReportList(cluster string) (*v1alpha1.RbacAssessmentReportList, error) {
	out := &v1alpha1.RbacAssessmentReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.RbacAssessmentReports != nil {
			out.Items = append(out.Items, b.RbacAssessmentReports.Items...)
		}
	}
	return out, nil
}

// GetClusterRbacAssessmentReportList returns the merged cluster rbac assessment reports.
func GetClusterRbacAssessmentReportList(cluster string) (*v1alpha1.ClusterRbacAssessmentReportList, error) {
	out := &v1alpha1.ClusterRbacAssessmentReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.ClusterRbacAssessmentReports != nil {
			out.Items = append(out.Items, b.ClusterRbacAssessmentReports.Items...)
		}
	}
	return out, nil
}

// GetConfigAuditReportList returns the merged config audit reports.
func GetConfigAuditReportList(cluster string) (*v1alpha1.ConfigAuditReportList, error) {
	out := &v1alpha1.ConfigAuditReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.ConfigAuditReports != nil {
			out.Items = append(out.Items, b.ConfigAuditReports.Items...)
		}
	}
	return out, nil
}

// GetClusterInfraAssessmentReportList returns the merged cluster infra assessment reports.
func GetClusterInfraAssessmentReportList(cluster string) (*v1alpha1.ClusterInfraAssessmentReportList, error) {
	out := &v1alpha1.ClusterInfraAssessmentReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.ClusterInfraAssessmentReports != nil {
			out.Items = append(out.Items, b.ClusterInfraAssessmentReports.Items...)
		}
	}
	return out, nil
}

// GetExposedSecretReportList returns the merged exposed secret reports.
func GetExposedSecretReportList(cluster string) (*v1alpha1.ExposedSecretReportList, error) {
	out := &v1alpha1.ExposedSecretReportList{}
	for _, b := range bundlesFor(cluster) {
		if b.ExposedSecretReports != nil {
			out.Items = append(out.Items, b.ExposedSecretReports.Items...)
		}
	}
	return out, nil
}

// GetContainerImagesMap returns the merged running-image map for the selected
// cluster (or all clusters). When the same image key appears in multiple
// clusters, their resource sets are unioned and every owning cluster is recorded
// in Clusters so the view layer can attribute unscanned images to their cluster.
func GetContainerImagesMap(cluster string) (map[string]kube.ContainerImage, error) {
	provider.mu.RLock()
	defer provider.mu.RUnlock()

	merged := map[string]kube.ContainerImage{}
	add := func(clusterName string, images map[string]kube.ContainerImage) {
		for k, v := range images {
			existing, ok := merged[k]
			if !ok {
				resources := make(map[kube.ResourceMetadata]struct{}, len(v.Resources))
				for r := range v.Resources {
					resources[r] = struct{}{}
				}
				clusters := map[string]struct{}{}
				if clusterName != "" {
					clusters[clusterName] = struct{}{}
				}
				merged[k] = kube.ContainerImage{Name: v.Name, Tag: v.Tag, Digest: v.Digest, Resources: resources, Clusters: clusters}
				continue
			}
			for r := range v.Resources {
				existing.Resources[r] = struct{}{}
			}
			if clusterName != "" {
				existing.Clusters[clusterName] = struct{}{}
			}
		}
	}

	if cluster != "" {
		if b, ok := provider.bundles[cluster]; ok {
			add(cluster, b.ContainerImages)
		}
	} else {
		for name, b := range provider.bundles {
			add(name, b.ContainerImages)
		}
	}
	return merged, nil
}

// stampCluster records the owning cluster on every report item's labels so the
// view layer can surface it without changing the underlying v1alpha1 types.
func stampCluster(b *store.Bundle, cluster string) {
	if b.VulnerabilityReports != nil {
		for i := range b.VulnerabilityReports.Items {
			setClusterLabel(&b.VulnerabilityReports.Items[i].ObjectMeta, cluster)
		}
	}
	if b.ComplianceReports != nil {
		for i := range b.ComplianceReports.Items {
			setClusterLabel(&b.ComplianceReports.Items[i].ObjectMeta, cluster)
		}
	}
	if b.RbacAssessmentReports != nil {
		for i := range b.RbacAssessmentReports.Items {
			setClusterLabel(&b.RbacAssessmentReports.Items[i].ObjectMeta, cluster)
		}
	}
	if b.ClusterRbacAssessmentReports != nil {
		for i := range b.ClusterRbacAssessmentReports.Items {
			setClusterLabel(&b.ClusterRbacAssessmentReports.Items[i].ObjectMeta, cluster)
		}
	}
	if b.ConfigAuditReports != nil {
		for i := range b.ConfigAuditReports.Items {
			setClusterLabel(&b.ConfigAuditReports.Items[i].ObjectMeta, cluster)
		}
	}
	if b.ClusterInfraAssessmentReports != nil {
		for i := range b.ClusterInfraAssessmentReports.Items {
			setClusterLabel(&b.ClusterInfraAssessmentReports.Items[i].ObjectMeta, cluster)
		}
	}
	if b.ExposedSecretReports != nil {
		for i := range b.ExposedSecretReports.Items {
			setClusterLabel(&b.ExposedSecretReports.Items[i].ObjectMeta, cluster)
		}
	}
}

func setClusterLabel(m *metav1.ObjectMeta, cluster string) {
	if m.Labels == nil {
		m.Labels = map[string]string{}
	}
	m.Labels[utils.ClusterLabel] = cluster
}
