package images

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
)

// TestGetViewUnscannedClusterAttribution verifies that an unscanned image
// (present only in the running-image map, not in any vulnerability report) is
// attributed to the cluster(s) it runs in.
func TestGetViewUnscannedClusterAttribution(t *testing.T) {
	key := utils.AssembleImageFullName("", "alpine", "3.19", "abc123")
	imagesMap := map[string]kube.ContainerImage{
		key: {
			Name:      "alpine",
			Tag:       "3.19",
			Digest:    "abc123",
			Resources: map[kube.ResourceMetadata]struct{}{},
			Clusters:  map[string]struct{}{"clusterA": {}, "clusterB": {}},
		},
	}

	view := GetView(&v1alpha1.VulnerabilityReportList{}, imagesMap, Filters{})
	if len(view) != 1 {
		t.Fatalf("expected 1 image, got %d", len(view))
	}
	d := view[0]
	if !d.Unscanned {
		t.Fatalf("expected the image to be marked unscanned")
	}
	if got := d.ClusterCount(); got != 2 {
		t.Fatalf("expected unscanned image attributed to 2 clusters, got %d", got)
	}
	if got := d.ClusterList(); got != "clusterA, clusterB" {
		t.Fatalf("expected cluster list %q, got %q", "clusterA, clusterB", got)
	}
}
