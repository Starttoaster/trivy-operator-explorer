package mcp

import (
	"context"
	"fmt"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/source"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
	imageview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/image"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
)

// defaultRegistry mirrors the default applied by the REST API when no
// registry is supplied with an image reference.
const defaultRegistry = "index.docker.io"

// registerTools attaches every MCP tool to the given server. Tools are
// declared via mcp.AddTool so the SDK auto-generates input/output JSON
// Schemas from the Go types.
func registerTools(s *mcpsdk.Server) {
	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_clusters",
		Description: "List the cluster names whose trivy-operator reports are currently available. " +
			"Use a returned name as the optional `cluster` argument on the other tools to scope " +
			"results to a single cluster; omit `cluster` to aggregate across all of them.",
	}, listClustersTool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_images",
		Description: "List every container image known to the cluster (scanned by trivy-operator " +
			"plus any unscanned images detected via running pods). Returns per-image summary " +
			"with vulnerability counts grouped by severity, fix-available counts, OS metadata, " +
			"and the workloads that use the image. Supports the same filters as the /api/v1/images " +
			"REST endpoint.",
	}, listImagesTool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "get_image",
		Description: "Get the full vulnerability list for a single image. Identify the image either by " +
			"`ref` (canonical fully-qualified ref like 'index.docker.io/library/nginx:1.27@sha256:...') " +
			"or by the split `registry`/`repository`/`tag`/`digest` parameters. Each returned " +
			"Vulnerability includes Trivy classification fields (class, package_type, pkg_path, " +
			"pkg_purl) so clients can distinguish OS-package CVEs from application-package CVEs.",
	}, getImageTool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_cves",
		Description: "Aggregate every CVE in the cluster across all scanned images. Supports filtering by " +
			"severity, fix availability, Trivy class (e.g. 'os-pkgs' for base-OS-introduced or " +
			"'lang-pkgs' for application-introduced), package type, and ignore state. Sort by " +
			"'pressure_desc' (default, score * affected images), 'score_desc', " +
			"'affected_count_desc', or 'cve_id_asc'. Use limit=N for top-N queries.",
	}, listCVEsTool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_images_with_cve",
		Description: "Look up a single CVE by ID and return the list of images it affects, including " +
			"per-image vulnerable/fixed versions, package class, and ignore state. Returns " +
			"found=false when no scanned image contains the CVE.",
	}, listImagesWithCVETool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "list_ignored_cves",
		Description: "List all (image, CVE) pairs that have been ignored, with optional filtering by " +
			"registry/repository/tag. Used to inspect or audit the persisted ignore list before " +
			"making changes.",
	}, listIgnoredCVEsTool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "ignore_cves",
		Description: "Mark one or more CVEs as ignored for a specific image (identified by registry/" +
			"repository/tag, or by canonical `ref`). Idempotent: rows that already exist are " +
			"skipped, and the response reports how many rows were newly inserted. A non-empty " +
			"`reason` is required so the ignore list stays auditable.",
	}, ignoreCVEsTool)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name: "unignore_cves",
		Description: "Remove one or more ignored-CVE rows for a specific image (identified by registry/" +
			"repository/tag, or by canonical `ref`). Idempotent: missing rows are silently skipped " +
			"and the response reports how many rows were actually deleted.",
	}, unignoreCVEsTool)
}

// ----- list_clusters -----

// listClustersParams intentionally has no fields; list_clusters takes no input.
type listClustersParams struct{}

// listClustersResult wraps the cluster-name slice in an object so the
// auto-generated MCP output schema has type "object", which the spec requires
// for structured tool output.
type listClustersResult struct {
	Total    int      `json:"total"`
	Clusters []string `json:"clusters"`
}

func listClustersTool(_ context.Context, _ *mcpsdk.CallToolRequest, _ listClustersParams) (*mcpsdk.CallToolResult, listClustersResult, error) {
	clusters := source.ListClusters()
	if clusters == nil {
		clusters = []string{}
	}
	return nil, listClustersResult{Total: len(clusters), Clusters: clusters}, nil
}

// ----- list_images -----

type listImagesParams struct {
	Cluster     string   `json:"cluster,omitempty" jsonschema:"optional cluster name to scope results to; empty means aggregate across all clusters"`
	Severity    string   `json:"severity,omitempty" jsonschema:"optional severity filter (critical|high|medium|low), case-insensitive; keeps only images that contain at least one non-ignored CVE of this severity"`
	HasFix      bool     `json:"has_fix,omitempty" jsonschema:"when true, only count CVEs that have a fixed version available"`
	ShowIgnored bool     `json:"show_ignored,omitempty" jsonschema:"when true, include CVEs marked as ignored in the database"`
	OSFamily    string   `json:"os_family,omitempty" jsonschema:"optional case-insensitive exact filter on detected OS family (e.g. 'debian', 'alpine')"`
	EOSL        *bool    `json:"eosl,omitempty" jsonschema:"tri-state filter: true returns only end-of-service-life images, false returns only non-EOSL images, omitted returns both"`
	CVEIDs      []string `json:"cve_ids,omitempty" jsonschema:"keep only images that contain ALL listed CVE IDs (logical AND); ignored CVEs only count when show_ignored is true"`
}

// listImagesResult wraps the underlying slice view in an object so the
// auto-generated MCP output schema has type "object", which the spec
// requires for structured tool output.
type listImagesResult struct {
	Total  int             `json:"total"`
	Images imagesview.View `json:"images"`
}

func listImagesTool(_ context.Context, _ *mcpsdk.CallToolRequest, in listImagesParams) (*mcpsdk.CallToolResult, listImagesResult, error) {
	reports, err := getReportsOrError(in.Cluster)
	if err != nil {
		return nil, listImagesResult{}, err
	}
	imagesMap, err := source.GetContainerImagesMap(in.Cluster)
	if err != nil {
		log.Logger.Error("MCP list_images: error getting a list of running images", "error", err.Error())
	}
	view := imagesview.GetView(reports, imagesMap, imagesview.Filters{
		HasFix:      in.HasFix,
		ShowIgnored: in.ShowIgnored,
		Severity:    in.Severity,
		OSFamily:    in.OSFamily,
		EOSL:        in.EOSL,
		CVEIDs:      in.CVEIDs,
	})
	return nil, listImagesResult{Total: len(view), Images: view}, nil
}

// ----- get_image -----

type getImageParams struct {
	Cluster     string   `json:"cluster,omitempty" jsonschema:"optional cluster name to scope results to; empty means aggregate across all clusters"`
	Ref         string   `json:"ref,omitempty" jsonschema:"canonical image ref like 'index.docker.io/library/nginx:1.27@sha256:...'; preferred when supplied; must include @digest"`
	Registry    string   `json:"registry,omitempty" jsonschema:"image registry host; defaults to 'index.docker.io' when empty and ref is not supplied"`
	Repository  string   `json:"repository,omitempty" jsonschema:"image repository (required when ref is not supplied)"`
	Tag         string   `json:"tag,omitempty" jsonschema:"image tag"`
	Digest      string   `json:"digest,omitempty" jsonschema:"image digest (required when ref is not supplied)"`
	Severity    string   `json:"severity,omitempty" jsonschema:"optional severity filter (critical|high|medium|low), case-insensitive"`
	HasFix      bool     `json:"has_fix,omitempty" jsonschema:"when true, only return CVEs with a fixed version available"`
	ShowIgnored bool     `json:"show_ignored,omitempty" jsonschema:"when true, include CVEs marked as ignored in the database"`
	Resources   []string `json:"resources,omitempty" jsonschema:"restrict to CVEs affecting the named installed package(s)"`
}

type getImageResult struct {
	Found bool            `json:"found"`
	Image *imageview.View `json:"image,omitempty"`
}

func getImageTool(_ context.Context, _ *mcpsdk.CallToolRequest, in getImageParams) (*mcpsdk.CallToolResult, getImageResult, error) {
	registry, repository, tag, digest, err := resolveImageRef(in.Ref, in.Registry, in.Repository, in.Tag, in.Digest)
	if err != nil {
		return nil, getImageResult{}, err
	}

	reports, err := getReportsOrError(in.Cluster)
	if err != nil {
		return nil, getImageResult{}, err
	}

	ignoredCVEs, err := db.GetIgnoredCVEsForImage(registry, repository, tag)
	if err != nil {
		log.Logger.Error("MCP get_image: error getting ignored CVEs", "error", err.Error())
		ignoredCVEs = nil
	}

	imageName := utils.AssembleImageFullName(
		utils.FormatPrettyImageRegistry(registry),
		utils.FormatPrettyImageRepo(repository),
		tag,
		digest,
	)

	view, found := imageview.GetView(reports, imageview.Filters{
		Name:        imageName,
		Digest:      digest,
		Severity:    in.Severity,
		HasFix:      in.HasFix,
		ShowIgnored: in.ShowIgnored,
		Resources:   in.Resources,
	}, ignoredCVEs)
	if !found {
		return nil, getImageResult{Found: false}, nil
	}
	return nil, getImageResult{Found: true, Image: &view}, nil
}

// ----- list_cves -----

func listCVEsTool(_ context.Context, _ *mcpsdk.CallToolRequest, in listCVEsParams) (*mcpsdk.CallToolResult, listCVEsResult, error) {
	reports, err := getReportsOrError(in.Cluster)
	if err != nil {
		return nil, listCVEsResult{}, err
	}
	return nil, runListCVEs(reports, in), nil
}

// ----- list_images_with_cve -----

func listImagesWithCVETool(_ context.Context, _ *mcpsdk.CallToolRequest, in listImagesWithCVEParams) (*mcpsdk.CallToolResult, listImagesWithCVEResult, error) {
	if strings.TrimSpace(in.CVEID) == "" {
		return nil, listImagesWithCVEResult{}, fmt.Errorf("cve_id is required")
	}
	reports, err := getReportsOrError(in.Cluster)
	if err != nil {
		return nil, listImagesWithCVEResult{}, err
	}
	return nil, runListImagesWithCVE(reports, in), nil
}

// ----- list_ignored_cves -----

type listIgnoredCVEsParams struct {
	Registry   string `json:"registry,omitempty" jsonschema:"optional registry filter (exact)"`
	Repository string `json:"repository,omitempty" jsonschema:"optional repository filter (exact)"`
	Tag        string `json:"tag,omitempty" jsonschema:"optional tag filter (exact)"`
}

type listIgnoredCVEsResult struct {
	Total   int                            `json:"total"`
	Ignores []db.IgnoredImageVulnerability `json:"ignores"`
}

func listIgnoredCVEsTool(_ context.Context, _ *mcpsdk.CallToolRequest, in listIgnoredCVEsParams) (*mcpsdk.CallToolResult, listIgnoredCVEsResult, error) {
	rows, err := db.ListIgnoredImageVulnerabilities(db.IgnoredImageVulnerabilityFilter{
		Registry:   in.Registry,
		Repository: in.Repository,
		Tag:        in.Tag,
	})
	if err != nil {
		log.Logger.Error("MCP list_ignored_cves: error listing ignores", "error", err.Error())
		return nil, listIgnoredCVEsResult{}, err
	}
	if rows == nil {
		rows = []db.IgnoredImageVulnerability{}
	}
	return nil, listIgnoredCVEsResult{Total: len(rows), Ignores: rows}, nil
}

// ----- ignore_cves -----

type ignoreCVEsParams struct {
	Ref        string   `json:"ref,omitempty" jsonschema:"canonical image ref like 'index.docker.io/library/nginx:1.27@sha256:...'; preferred when supplied"`
	Registry   string   `json:"registry,omitempty" jsonschema:"image registry host; defaults to 'index.docker.io' when empty and ref is not supplied"`
	Repository string   `json:"repository,omitempty" jsonschema:"image repository (required when ref is not supplied)"`
	Tag        string   `json:"tag,omitempty" jsonschema:"image tag (required when ref is not supplied)"`
	CVEIDs     []string `json:"cve_ids" jsonschema:"required non-empty list of CVE IDs to ignore for this image"`
	Reason     string   `json:"reason" jsonschema:"required human-readable reason recorded alongside the ignore entries (e.g. 'base OS CVE, not in execution path')"`
}

type ignoreCVEsResult struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Inserted   int64  `json:"inserted"`
}

func ignoreCVEsTool(_ context.Context, _ *mcpsdk.CallToolRequest, in ignoreCVEsParams) (*mcpsdk.CallToolResult, ignoreCVEsResult, error) {
	registry, repository, tag, err := resolveIgnoreTarget(in.Ref, in.Registry, in.Repository, in.Tag)
	if err != nil {
		return nil, ignoreCVEsResult{}, err
	}
	if len(in.CVEIDs) == 0 {
		return nil, ignoreCVEsResult{}, fmt.Errorf("cve_ids must contain at least one CVE ID")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, ignoreCVEsResult{}, fmt.Errorf("reason is required")
	}
	inserted, err := db.BulkInsertIgnoredImageVulnerabilities(registry, repository, tag, in.Reason, in.CVEIDs)
	if err != nil {
		log.Logger.Error("MCP ignore_cves: insert failed", "error", err.Error())
		return nil, ignoreCVEsResult{}, err
	}
	return nil, ignoreCVEsResult{
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
		Inserted:   inserted,
	}, nil
}

// ----- unignore_cves -----

type unignoreCVEsParams struct {
	Ref        string   `json:"ref,omitempty" jsonschema:"canonical image ref like 'index.docker.io/library/nginx:1.27@sha256:...'; preferred when supplied"`
	Registry   string   `json:"registry,omitempty" jsonschema:"image registry host; defaults to 'index.docker.io' when empty and ref is not supplied"`
	Repository string   `json:"repository,omitempty" jsonschema:"image repository (required when ref is not supplied)"`
	Tag        string   `json:"tag,omitempty" jsonschema:"image tag (required when ref is not supplied)"`
	CVEIDs     []string `json:"cve_ids" jsonschema:"required non-empty list of CVE IDs to remove from the ignore list for this image"`
}

type unignoreCVEsResult struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Deleted    int64  `json:"deleted"`
}

func unignoreCVEsTool(_ context.Context, _ *mcpsdk.CallToolRequest, in unignoreCVEsParams) (*mcpsdk.CallToolResult, unignoreCVEsResult, error) {
	registry, repository, tag, err := resolveIgnoreTarget(in.Ref, in.Registry, in.Repository, in.Tag)
	if err != nil {
		return nil, unignoreCVEsResult{}, err
	}
	if len(in.CVEIDs) == 0 {
		return nil, unignoreCVEsResult{}, fmt.Errorf("cve_ids must contain at least one CVE ID")
	}
	deleted, err := db.BulkDeleteIgnoredImageVulnerabilities(registry, repository, tag, in.CVEIDs)
	if err != nil {
		log.Logger.Error("MCP unignore_cves: delete failed", "error", err.Error())
		return nil, unignoreCVEsResult{}, err
	}
	return nil, unignoreCVEsResult{
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
		Deleted:    deleted,
	}, nil
}

// ----- helpers -----

// resolveImageRef normalizes the image identification inputs accepted by
// get_image. `ref` wins when supplied; otherwise the split parameters are
// used and `digest` is required (matching the REST /api/v1/image semantics).
func resolveImageRef(ref, registry, repository, tag, digest string) (string, string, string, string, error) {
	if ref != "" {
		r, repo, t, d, err := utils.ParseImageRef(ref)
		if err != nil {
			return "", "", "", "", fmt.Errorf("invalid ref: %w", err)
		}
		if d == "" {
			return "", "", "", "", fmt.Errorf("ref must include an @digest")
		}
		return r, repo, t, d, nil
	}
	if repository == "" {
		return "", "", "", "", fmt.Errorf("repository is required when ref is not supplied")
	}
	if digest == "" {
		return "", "", "", "", fmt.Errorf("digest is required when ref is not supplied")
	}
	if registry == "" {
		registry = defaultRegistry
	}
	return registry, repository, tag, digest, nil
}

// resolveIgnoreTarget normalizes the image identification inputs accepted by
// ignore_cves / unignore_cves. Tag is required (the persisted ignore list is
// keyed on (registry, repository, tag, cve_id), so a missing tag would make
// the row unreachable).
func resolveIgnoreTarget(ref, registry, repository, tag string) (string, string, string, error) {
	if ref != "" {
		r, repo, t, _, err := utils.ParseImageRef(ref)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid ref: %w", err)
		}
		registry, repository, tag = r, repo, t
	}
	if repository == "" {
		return "", "", "", fmt.Errorf("repository is required when ref is not supplied")
	}
	if tag == "" {
		return "", "", "", fmt.Errorf("tag is required (the ignore list is keyed on registry/repository/tag/cve_id)")
	}
	if registry == "" {
		registry = defaultRegistry
	}
	return registry, repository, tag, nil
}
