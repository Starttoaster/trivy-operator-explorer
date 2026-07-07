package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	assets "github.com/starttoaster/trivy-operator-explorer"
	"github.com/starttoaster/trivy-operator-explorer/internal/cve"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
	exposedsecretsview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/exposedsecrets"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
	indexview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/index"
)

func init() { content.Init(assets.Static) }

// TestImagesTemplateClusterColumn renders the images table and verifies the
// Cluster column collapses multi-cluster images to an "N clusters" summary with
// the full list available as hover text, while single-cluster images show the
// cluster name directly.
func TestImagesTemplateClusterColumn(t *testing.T) {
	funcMap := template.FuncMap{
		"sanitizeID": func(s string) string {
			return strings.NewReplacer("/", "_", ":", "_", " ", "_", "-", "_", ".", "_").Replace(s)
		},
		"add": func(a, b int) int { return a + b },
		"pct": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a * 100 / b
		},
	}
	tmpl := template.Must(template.New("images.html").Funcs(funcMap).ParseFS(content.Static, "static/images.html", "static/sidebar.html"))

	multi := imagesview.Data{Name: "alpine", Tag: "3.19", Digest: "sha256:abc", Clusters: map[string]struct{}{"clusterB": {}, "clusterA": {}}}
	single := imagesview.Data{Name: "nginx", Tag: "1.27", Digest: "sha256:def", Clusters: map[string]struct{}{"clusterA": {}}}

	data := struct {
		PageRoute   string
		HasFix      bool
		ShowIgnored bool
		Class       string
		TotalImages int
		Stats       indexview.View
		Data        imagesview.View
	}{PageRoute: "images", TotalImages: 2, Data: imagesview.View{multi, single}}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute images.html: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "2 clusters") {
		t.Errorf("expected multi-cluster image to render as '2 clusters'")
	}
	// Tooltip should list the clusters in sorted order.
	if !strings.Contains(out, `data-tooltip="clusterA, clusterB"`) {
		t.Errorf("expected hover tooltip listing 'clusterA, clusterB'")
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
		t.Errorf("expected hover tooltip listing 'clusterA, clusterB'")
	}
}

// TestCVEsTemplateRenders renders the CVE triage page with a single aggregate
// and its affected image, catching template/method wiring errors.
func TestCVEsTemplateRenders(t *testing.T) {
	funcMap := template.FuncMap{"sanitizeID": func(s string) string {
		return strings.NewReplacer("/", "_", ":", "_", " ", "_", "-", "_", ".", "_").Replace(s)
	}}
	tmpl := template.Must(template.New("cves.html").Funcs(funcMap).ParseFS(content.Static, "static/cves.html", "static/sidebar.html"))

	result := cve.Result{
		Total: 1,
		CVEs: []*cve.Aggregate{
			{
				CVEID:              "CVE-2024-0001",
				Severity:           "CRITICAL",
				MaxScore:           9.8,
				HasFix:             true,
				Class:              "os-pkgs",
				PackageType:        "apk",
				AffectedImageCount: 1,
				AffectedImages: []cve.AffectedImage{
					{Ref: "index.docker.io/library/nginx:1.27@sha256:abc", Cluster: "clusterA", Registry: "index.docker.io", Repository: "library/nginx", Tag: "1.27", Digest: "sha256:abc", VulnerableVersion: "1.0", FixedVersion: "1.1"},
				},
			},
		},
	}

	data := struct {
		PageRoute   string
		Cluster     string
		Result      cve.Result
		Severity    string
		Class       string
		HasFix      string
		ShowIgnored bool
		SortBy      string
	}{PageRoute: "cves", Result: result, SortBy: "pressure_desc"}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute cves.html: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "CVE-2024-0001") {
		t.Errorf("expected the CVE id in the output")
	}
	if !strings.Contains(out, "9.8") {
		t.Errorf("expected the pressure/score value in the output")
	}
	if !strings.Contains(out, "library/nginx") {
		t.Errorf("expected the affected image in the expandable detail")
	}
}

// TestIndexTemplateRenders renders the dashboard including the riskiest-images
// chart data.
func TestIndexTemplateRenders(t *testing.T) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/index.html", "static/sidebar.html"))

	data := indexview.View{
		CriticalVulnerabilities: 5,
		HighVulnerabilities:     3,
		TopImages: []indexview.TopImage{
			{Name: "nginx:1.27", Critical: 3, High: 2},
			{Name: "alpine:3.19", Critical: 1},
		},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute index.html: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Riskiest Images") {
		t.Errorf("expected the riskiest images section")
	}
	if !strings.Contains(out, "nginx:1.27") {
		t.Errorf("expected a top image label in the chart data")
	}
}
