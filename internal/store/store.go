// Package store persists and retrieves trivy-operator report bundles in an S3
// bucket. Objects are laid out as:
//
//	<prefix>/<cluster>/<name>.json
//
// where <name> is one object per report type (plus containerimages.json and
// meta.json). This makes the bucket multi-tenant: many clusters' collectors can
// write into the same bucket under their own cluster prefix, and the frontend
// discovers clusters by listing the common prefixes under <prefix>/.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
)

// Object names written under <prefix>/<cluster>/.
const (
	objVulnerabilityReports          = "vulnerabilityreports.json"
	objComplianceReports             = "clustercompliancereports.json"
	objRbacAssessmentReports         = "rbacassessmentreports.json"
	objClusterRbacAssessmentReports  = "clusterrbacassessmentreports.json"
	objConfigAuditReports            = "configauditreports.json"
	objClusterInfraAssessmentReports = "clusterinfraassessmentreports.json"
	objExposedSecretReports          = "exposedsecretreports.json"
	objContainerImages               = "containerimages.json"
	objMeta                          = "meta.json"
)

// errNotFound is returned internally when an object does not exist. Callers
// treat missing report objects as empty lists rather than hard failures so a
// cluster that has never produced (say) exposed-secret reports still loads.
var errNotFound = errors.New("object not found")

// Bundle is the full set of report data for a single cluster.
type Bundle struct {
	VulnerabilityReports          *v1alpha1.VulnerabilityReportList
	ComplianceReports             *v1alpha1.ClusterComplianceReportList
	RbacAssessmentReports         *v1alpha1.RbacAssessmentReportList
	ClusterRbacAssessmentReports  *v1alpha1.ClusterRbacAssessmentReportList
	ConfigAuditReports            *v1alpha1.ConfigAuditReportList
	ClusterInfraAssessmentReports *v1alpha1.ClusterInfraAssessmentReportList
	ExposedSecretReports          *v1alpha1.ExposedSecretReportList
	ContainerImages               map[string]kube.ContainerImage
}

// Meta is a small manifest object written alongside each cluster's reports so
// operators can see when a cluster last synced and with what collector version.
type Meta struct {
	Cluster  string    `json:"cluster"`
	SyncedAt time.Time `json:"synced_at"`
	Version  string    `json:"version"`
}

// resourceMetadataDTO is the JSON-safe representation of kube.ResourceMetadata.
type resourceMetadataDTO struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// containerImageDTO is the JSON-safe representation of kube.ContainerImage. The
// live type keys its Resources by a struct, which JSON cannot marshal as a map
// key, so we flatten it to a slice on the wire.
type containerImageDTO struct {
	Name      string                `json:"name"`
	Tag       string                `json:"tag"`
	Digest    string                `json:"digest"`
	Resources []resourceMetadataDTO `json:"resources"`
}

// Client wraps an S3 client bound to a bucket + key prefix.
type Client struct {
	s3     *s3.Client
	bucket string
	prefix string
}

// New constructs a store client using the standard AWS credential chain
// (environment, shared config, and in-cluster IRSA/web-identity). Region may be
// empty to defer to the environment/instance configuration.
func New(ctx context.Context, bucket, prefix, region string) (*Client, error) {
	if bucket == "" {
		return nil, errors.New("s3 bucket is required")
	}

	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("error loading AWS config: %w", err)
	}

	return &Client{
		s3:     s3.NewFromConfig(cfg),
		bucket: bucket,
		prefix: strings.Trim(prefix, "/"),
	}, nil
}

// key builds the full object key for a cluster + object name.
func (c *Client) key(cluster, name string) string {
	if c.prefix == "" {
		return path.Join(cluster, name)
	}
	return path.Join(c.prefix, cluster, name)
}

// clusterPrefix is the S3 listing prefix that enumerates cluster directories.
func (c *Client) clusterPrefix() string {
	if c.prefix == "" {
		return ""
	}
	return c.prefix + "/"
}

// WriteBundle persists every populated field of the bundle plus a meta object.
func (c *Client) WriteBundle(ctx context.Context, cluster string, b *Bundle, version string) error {
	writes := []struct {
		name string
		body any
	}{
		{objVulnerabilityReports, b.VulnerabilityReports},
		{objComplianceReports, b.ComplianceReports},
		{objRbacAssessmentReports, b.RbacAssessmentReports},
		{objClusterRbacAssessmentReports, b.ClusterRbacAssessmentReports},
		{objConfigAuditReports, b.ConfigAuditReports},
		{objClusterInfraAssessmentReports, b.ClusterInfraAssessmentReports},
		{objExposedSecretReports, b.ExposedSecretReports},
		{objContainerImages, containerImagesToDTO(b.ContainerImages)},
	}
	for _, w := range writes {
		if w.body == nil {
			continue
		}
		if err := c.putJSON(ctx, c.key(cluster, w.name), w.body); err != nil {
			return fmt.Errorf("error writing %s for cluster %s: %w", w.name, cluster, err)
		}
	}

	meta := Meta{Cluster: cluster, SyncedAt: time.Now().UTC(), Version: version}
	if err := c.putJSON(ctx, c.key(cluster, objMeta), meta); err != nil {
		return fmt.Errorf("error writing meta for cluster %s: %w", cluster, err)
	}
	return nil
}

// ListClusters returns the cluster names present in the bucket, discovered via
// the common prefixes under the configured key prefix.
func (c *Client) ListClusters(ctx context.Context) ([]string, error) {
	p := c.clusterPrefix()
	paginator := s3.NewListObjectsV2Paginator(c.s3, &s3.ListObjectsV2Input{
		Bucket:    aws.String(c.bucket),
		Prefix:    aws.String(p),
		Delimiter: aws.String("/"),
	})

	var clusters []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error listing clusters: %w", err)
		}
		for _, cp := range page.CommonPrefixes {
			if cp.Prefix == nil {
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(*cp.Prefix, p), "/")
			if name != "" {
				clusters = append(clusters, name)
			}
		}
	}
	return clusters, nil
}

// LoadCluster reads and deserializes every report object for a cluster. Missing
// objects are treated as empty lists so partially-populated clusters still load.
func (c *Client) LoadCluster(ctx context.Context, cluster string) (*Bundle, error) {
	b := &Bundle{
		VulnerabilityReports:          &v1alpha1.VulnerabilityReportList{},
		ComplianceReports:             &v1alpha1.ClusterComplianceReportList{},
		RbacAssessmentReports:         &v1alpha1.RbacAssessmentReportList{},
		ClusterRbacAssessmentReports:  &v1alpha1.ClusterRbacAssessmentReportList{},
		ConfigAuditReports:            &v1alpha1.ConfigAuditReportList{},
		ClusterInfraAssessmentReports: &v1alpha1.ClusterInfraAssessmentReportList{},
		ExposedSecretReports:          &v1alpha1.ExposedSecretReportList{},
		ContainerImages:               map[string]kube.ContainerImage{},
	}

	reads := []struct {
		name string
		into any
	}{
		{objVulnerabilityReports, b.VulnerabilityReports},
		{objComplianceReports, b.ComplianceReports},
		{objRbacAssessmentReports, b.RbacAssessmentReports},
		{objClusterRbacAssessmentReports, b.ClusterRbacAssessmentReports},
		{objConfigAuditReports, b.ConfigAuditReports},
		{objClusterInfraAssessmentReports, b.ClusterInfraAssessmentReports},
		{objExposedSecretReports, b.ExposedSecretReports},
	}
	for _, r := range reads {
		if err := c.getJSON(ctx, c.key(cluster, r.name), r.into); err != nil && !errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("error reading %s for cluster %s: %w", r.name, cluster, err)
		}
	}

	var imagesDTO map[string]containerImageDTO
	if err := c.getJSON(ctx, c.key(cluster, objContainerImages), &imagesDTO); err != nil && !errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("error reading %s for cluster %s: %w", objContainerImages, cluster, err)
	}
	b.ContainerImages = containerImagesFromDTO(imagesDTO)

	return b, nil
}

func (c *Client) putJSON(ctx context.Context, key string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshaling object: %w", err)
	}
	_, err = c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("error putting object %s: %w", key, err)
	}
	return nil
}

func (c *Client) getJSON(ctx context.Context, key string, into any) error {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *s3types.NoSuchKey
		var nf *s3types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			return errNotFound
		}
		return fmt.Errorf("error getting object %s: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return fmt.Errorf("error reading object body %s: %w", key, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("error unmarshaling object %s: %w", key, err)
	}
	return nil
}

func containerImagesToDTO(m map[string]kube.ContainerImage) map[string]containerImageDTO {
	if m == nil {
		return nil
	}
	out := make(map[string]containerImageDTO, len(m))
	for k, v := range m {
		resources := make([]resourceMetadataDTO, 0, len(v.Resources))
		for r := range v.Resources {
			resources = append(resources, resourceMetadataDTO{Kind: r.Kind, Name: r.Name, Namespace: r.Namespace})
		}
		out[k] = containerImageDTO{Name: v.Name, Tag: v.Tag, Digest: v.Digest, Resources: resources}
	}
	return out
}

func containerImagesFromDTO(m map[string]containerImageDTO) map[string]kube.ContainerImage {
	out := make(map[string]kube.ContainerImage, len(m))
	for k, v := range m {
		resources := make(map[kube.ResourceMetadata]struct{}, len(v.Resources))
		for _, r := range v.Resources {
			resources[kube.ResourceMetadata{Kind: r.Kind, Name: r.Name, Namespace: r.Namespace}] = struct{}{}
		}
		out[k] = kube.ContainerImage{Name: v.Name, Tag: v.Tag, Digest: v.Digest, Resources: resources}
	}
	return out
}
