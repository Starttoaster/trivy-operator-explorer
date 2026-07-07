package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	assets "github.com/starttoaster/trivy-operator-explorer"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
	exposedsecretsview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/exposedsecrets"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
)

func init() { content.Init(assets.Static) }

// TestImagesTemplateClusterColumn renders the images table and verifies the
// Cluster column collapses multi-cluster images to an "N clusters" summary with
// the full list available as hover text, while single-cluster images show the
// cluster name directly.
func TestImagesTemplateClusterColumn(t *testing.T) {
	funcMap := template.FuncMap{"sanitizeID": func(s string) string {
		return strings.NewReplacer("/", "_", ":", "_", " ", "_", "-", "_", ".", "_").Replace(s)
	}}
	tmpl := template.Must(template.New("images.html").Funcs(funcMap).ParseFS(content.Static, "static/images.html", "static/sidebar.html"))

	multi := imagesview.Data{Name: "alpine", Tag: "3.19", Digest: "sha256:abc", Clusters: map[string]struct{}{"clusterB": {}, "clusterA": {}}}
	single := imagesview.Data{Name: "nginx", Tag: "1.27", Digest: "sha256:def", Clusters: map[string]struct{}{"clusterA": {}}}

	data := struct {
		PageRoute   string
		HasFix      bool
		ShowIgnored bool
		Data        imagesview.View
	}{PageRoute: "images", Data: imagesview.View{multi, single}}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute images.html: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "2 clusters") {
		t.Errorf("expected multi-cluster image to render as '2 clusters'")
	}
	// Tooltip should list the clusters in sorted order via the data-tooltip attr.
	if !strings.Contains(out, `data-tooltip="clusterA, clusterB"`) {
		t.Errorf("expected data-tooltip listing 'clusterA, clusterB'")
	}
}

// TestExposedSecretsTemplateClusterColumn does the same for the exposed-secrets
// table, which shares the cluster-column snippet.
func TestExposedSecretsTemplateClusterColumn(t *testing.T) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/exposedsecrets.html", "static/sidebar.html"))

	multi := exposedsecretsview.Data{Name: "alpine:3.19", Digest: "sha256:abc", Clusters: map[string]struct{}{"clusterB": {}, "clusterA": {}}}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, exposedsecretsview.View{multi}); err != nil {
		t.Fatalf("execute exposedsecrets.html: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "2 clusters") {
		t.Errorf("expected multi-cluster image to render as '2 clusters'")
	}
	if !strings.Contains(out, `data-tooltip="clusterA, clusterB"`) {
		t.Errorf("expected data-tooltip listing 'clusterA, clusterB'")
	}
}

// TestComplianceReportsTemplateClusterColumn verifies the compliance reports
// list shows a per-report cluster and scopes each report link to that cluster.
func TestComplianceReportsTemplateClusterColumn(t *testing.T) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/compliancereports.html", "static/sidebar.html"))

	view := complianceview.View{
		{Cluster: "clusterA", ID: "k8s-cis", Title: "CIS Kubernetes Benchmark"},
		{Cluster: "clusterB", ID: "k8s-cis", Title: "CIS Kubernetes Benchmark"},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		t.Fatalf("execute compliancereports.html: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "clusterA") || !strings.Contains(out, "clusterB") {
		t.Errorf("expected both cluster names in the compliance reports table")
	}
	if !strings.Contains(out, "id=k8s-cis&cluster=clusterA") {
		t.Errorf("expected the report link to be scoped to its cluster")
	}
}
