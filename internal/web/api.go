package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/source"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
	"github.com/starttoaster/trivy-operator-explorer/internal/version"
	clusterauditview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/clusteraudit"
	clusterauditsview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/clusteraudits"
	clusterroleview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/clusterrole"
	clusterrolesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/clusterroles"
	complianceview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/compliance"
	configauditview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/configaudit"
	configauditsview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/configaudits"
	exposedsecretview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/exposedsecret"
	exposedsecretsview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/exposedsecrets"
	imageview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/image"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
	indexview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/index"
	roleview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/role"
	rolesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/roles"
)

// healthResponse is the body returned by GET /api/v1/health.
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// apiHealthHandler is a cheap liveness probe. It deliberately does not touch
// the S3 store so the result is stable across backend reachability hiccups.
func apiHealthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Version: version.Version})
}

// apiClustersHandler returns the list of clusters currently cached from S3. The
// UI cluster selector uses this to populate its options.
func apiClustersHandler(w http.ResponseWriter, r *http.Request) {
	clusters := source.ListClusters()
	if clusters == nil {
		clusters = []string{}
	}
	writeJSON(w, http.StatusOK, clusters)
}

// apiStatusHandler returns per-cluster sync freshness (from each cluster's
// meta.json). The UI freshness indicator uses this.
func apiStatusHandler(w http.ResponseWriter, r *http.Request) {
	statuses := source.ClusterStatuses()
	if statuses == nil {
		statuses = []source.ClusterStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

// writeJSON serializes body to JSON and writes it to w with the given status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Logger.Error("failed to encode JSON response", "error", err)
	}
}

// writeJSONError writes a standardized JSON error body.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// methodGet returns an http.HandlerFunc that responds with 405 + JSON for any
// HTTP method other than GET (and HEAD, which Go's net/http normally serves
// automatically as a GET without a body). It exists so the read-only /api/v1/*
// endpoints can self-document their method.
func methodGet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET")
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h(w, r)
	}
}

// parseBoolQuery parses an optional bool query parameter, returning false if
// missing or unparseable (and logging a warning in the latter case).
func parseBoolQuery(name, raw string) bool {
	if raw == "" {
		return false
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		log.Logger.Warn("could not parse query parameter to bool type, ignoring filter", "param", name, "raw", raw, "error", err.Error())
		return false
	}
	return v
}

func apiIndexHandler(w http.ResponseWriter, r *http.Request) {
	// Catch unknown /api/v1/<subpath> routes so they don't silently serve the
	// index payload.
	if r.URL.Path != "/api/v1/" && r.URL.Path != "/api/v1" {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	cluster := r.URL.Query().Get("cluster")

	vulnerabilityData, err := source.GetVulnerabilityReportList(cluster)
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerability reports")
		return
	}
	imagesView := imagesview.GetView(vulnerabilityData, nil, imagesview.Filters{})

	complianceData, err := source.GetComplianceReportList(cluster)
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list compliance reports")
		return
	}
	complianceData2 := complianceview.GetView(complianceData)

	writeJSON(w, http.StatusOK, indexview.GetView(imagesView, complianceData2))
}

func apiImagesHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hasFixBool := parseBoolQuery("hasfix", q.Get("hasfix"))
	showIgnoredBool := parseBoolQuery("showignored", q.Get("showignored"))

	var eosl *bool
	if raw := q.Get("eosl"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			log.Logger.Warn("could not parse eosl query parameter to bool type, ignoring filter", "raw", raw, "error", err.Error())
		} else {
			eosl = &v
		}
	}

	cluster := q.Get("cluster")
	data, err := source.GetVulnerabilityReportList(cluster)
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerability reports")
		return
	}
	imagesMap, err := source.GetContainerImagesMap(cluster)
	if err != nil {
		log.Logger.Error("error getting a list of running images", "error", err.Error())
	}

	view := imagesview.GetView(data, imagesMap, imagesview.Filters{
		HasFix:      hasFixBool,
		ShowIgnored: showIgnoredBool,
		Severity:    q.Get("severity"),
		OSFamily:    q.Get("os_family"),
		EOSL:        eosl,
		CVEIDs:      q["cve"],
		Class:       q.Get("class"),
	})
	writeJSON(w, http.StatusOK, view)
}

func apiImageHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var (
		imageRegistry   string
		imageRepository string
		imageTag        string
		imageDigest     string
	)

	// Prefer ?ref= when supplied; otherwise fall back to the split params.
	if ref := q.Get("ref"); ref != "" {
		var err error
		imageRegistry, imageRepository, imageTag, imageDigest, err = utils.ParseImageRef(ref)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid ref: "+err.Error())
			return
		}
		if imageDigest == "" {
			writeJSONError(w, http.StatusBadRequest, "ref must include an @digest")
			return
		}
	} else {
		imageRepository = q.Get("repository")
		if imageRepository == "" {
			writeJSONError(w, http.StatusBadRequest, "missing required query parameter: repository (or pass ref)")
			return
		}
		imageDigest = q.Get("digest")
		if imageDigest == "" {
			writeJSONError(w, http.StatusBadRequest, "missing required query parameter: digest (or pass ref)")
			return
		}
		imageTag = q.Get("tag")
		imageRegistry = q.Get("registry")
		if imageRegistry == "" {
			imageRegistry = "index.docker.io"
		}
	}

	severity := q.Get("severity")
	hasFixBool := parseBoolQuery("hasfix", q.Get("hasfix"))
	showIgnoredBool := parseBoolQuery("showignored", q.Get("showignored"))

	reports, err := source.GetVulnerabilityReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerability reports")
		return
	}

	ignoredCVEs, err := db.GetIgnoredCVEsForImage(imageRegistry, imageRepository, imageTag)
	if err != nil {
		log.Logger.Error("error getting ignored CVEs", "error", err.Error())
		ignoredCVEs = nil
	}

	imageName := utils.AssembleImageFullName(
		utils.FormatPrettyImageRegistry(imageRegistry),
		utils.FormatPrettyImageRepo(imageRepository),
		imageTag,
		imageDigest,
	)

	view, found := imageview.GetView(reports, imageview.Filters{
		Name:        imageName,
		Digest:      imageDigest,
		Severity:    severity,
		HasFix:      hasFixBool,
		ShowIgnored: showIgnoredBool,
		Resources:   q["resources"],
	}, ignoredCVEs)
	if !found {
		writeJSONError(w, http.StatusNotFound, "image not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func apiRolesHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	namespace := q.Get("namespace")

	reports, err := source.GetRbacAssessmentReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting RBACAssessmentReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list rbac assessment reports")
		return
	}
	writeJSON(w, http.StatusOK, rolesview.GetView(reports, rolesview.Filters{
		Namespace: namespace,
	}))
}

func apiRoleHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: name")
		return
	}
	namespace := q.Get("namespace")
	if namespace == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: namespace")
		return
	}
	severity := q.Get("severity")

	reports, err := source.GetRbacAssessmentReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting RBACAssessmentReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list rbac assessment reports")
		return
	}
	role, found := roleview.GetView(reports, roleview.Filters{
		Name:      name,
		Namespace: namespace,
		Severity:  severity,
	})
	if !found {
		writeJSONError(w, http.StatusNotFound, "role not found")
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func apiClusterrolesHandler(w http.ResponseWriter, r *http.Request) {
	reports, err := source.GetClusterRbacAssessmentReportList(r.URL.Query().Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting clusterrbacassessmentreports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list cluster rbac assessment reports")
		return
	}
	writeJSON(w, http.StatusOK, clusterrolesview.GetView(reports))
}

func apiClusterroleHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: name")
		return
	}
	severity := q.Get("severity")

	reports, err := source.GetClusterRbacAssessmentReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting clusterrbacassessmentreports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list cluster rbac assessment reports")
		return
	}
	role, found := clusterroleview.GetView(reports, clusterroleview.Filters{
		Name:     name,
		Severity: severity,
	})
	if !found {
		writeJSONError(w, http.StatusNotFound, "clusterrole not found")
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func apiConfigauditsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	namespace := q.Get("namespace")
	kind := q.Get("kind")

	reports, err := source.GetConfigAuditReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting configauditreports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list config audit reports")
		return
	}
	writeJSON(w, http.StatusOK, configauditsview.GetView(reports, configauditsview.Filters{
		Namespace: namespace,
		Kind:      kind,
	}))
}

func apiConfigauditHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: name")
		return
	}
	namespace := q.Get("namespace")
	if namespace == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: namespace")
		return
	}
	kind := q.Get("kind")
	if kind == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: kind")
		return
	}
	severity := q.Get("severity")

	reports, err := source.GetConfigAuditReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting configauditreports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list config audit reports")
		return
	}
	audit, found := configauditview.GetView(reports, configauditview.Filters{
		Name:      name,
		Namespace: namespace,
		Kind:      kind,
		Severity:  severity,
	})
	if !found {
		writeJSONError(w, http.StatusNotFound, "config audit not found")
		return
	}
	writeJSON(w, http.StatusOK, audit)
}

func apiClusterauditsHandler(w http.ResponseWriter, r *http.Request) {
	reports, err := source.GetClusterInfraAssessmentReportList(r.URL.Query().Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting clusterinfraassessmentreports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list cluster infra assessment reports")
		return
	}
	writeJSON(w, http.StatusOK, clusterauditsview.GetView(reports))
}

func apiClusterauditHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: name")
		return
	}
	kind := q.Get("kind")
	if kind == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: kind")
		return
	}
	severity := q.Get("severity")

	reports, err := source.GetClusterInfraAssessmentReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting clusterinfraassessmentreports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list cluster infra assessment reports")
		return
	}
	audit, found := clusterauditview.GetView(reports, clusterauditview.Filters{
		Name:     name,
		Kind:     kind,
		Severity: severity,
	})
	if !found {
		writeJSONError(w, http.StatusNotFound, "cluster audit not found")
		return
	}
	writeJSON(w, http.StatusOK, audit)
}

func apiExposedsecretsHandler(w http.ResponseWriter, r *http.Request) {
	data, err := source.GetExposedSecretReportList(r.URL.Query().Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting ExposedSecretReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list exposed secret reports")
		return
	}
	writeJSON(w, http.StatusOK, exposedsecretsview.GetView(data))
}

func apiExposedsecretHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	imageName := q.Get("image")
	if imageName == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: image")
		return
	}
	imageDigest := q.Get("digest")
	if imageDigest == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: digest")
		return
	}
	severity := q.Get("severity")

	data, err := source.GetExposedSecretReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting ExposedSecretReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list exposed secret reports")
		return
	}
	view, found := exposedsecretview.GetView(data, exposedsecretview.Filters{
		Name:     imageName,
		Digest:   imageDigest,
		Severity: severity,
	})
	if !found {
		writeJSONError(w, http.StatusNotFound, "exposed secret not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func apiComplianceReportsHandler(w http.ResponseWriter, r *http.Request) {
	data, err := source.GetComplianceReportList(r.URL.Query().Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list compliance reports")
		return
	}
	writeJSON(w, http.StatusOK, complianceview.GetView(data))
}

// ignoresRouter dispatches /api/v1/ignores by HTTP method.
func ignoresRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		apiListIgnoresHandler(w, r)
	case http.MethodPost:
		apiCreateIgnoresHandler(w, r)
	case http.MethodDelete:
		apiDeleteIgnoresHandler(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ignoresMutationRequest is the shared request body for POST and DELETE on
// /api/v1/ignores. For POST, Reason is required and CVEIDs must be non-empty.
// For DELETE, Reason is unused and CVEIDs must be non-empty.
type ignoresMutationRequest struct {
	Registry   string   `json:"registry"`
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	CVEIDs     []string `json:"cve_ids"`
	Reason     string   `json:"reason,omitempty"`
}

func apiListIgnoresHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := db.ListIgnoredImageVulnerabilities(db.IgnoredImageVulnerabilityFilter{
		Registry:   q.Get("registry"),
		Repository: q.Get("repository"),
		Tag:        q.Get("tag"),
	})
	if err != nil {
		log.Logger.Error("failed to list ignored image vulnerabilities", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list ignored vulnerabilities")
		return
	}
	if rows == nil {
		rows = []db.IgnoredImageVulnerability{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func apiCreateIgnoresHandler(w http.ResponseWriter, r *http.Request) {
	var req ignoresMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Logger.Error("failed to decode ignores POST body", "error", err)
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Repository == "" || req.Tag == "" || len(req.CVEIDs) == 0 || req.Reason == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required fields (repository, tag, cve_ids, reason)")
		return
	}
	registry := req.Registry
	if registry == "" {
		registry = "index.docker.io"
	}
	inserted, err := db.BulkInsertIgnoredImageVulnerabilities(registry, req.Repository, req.Tag, req.Reason, req.CVEIDs)
	if err != nil {
		log.Logger.Error("failed to insert ignored vulnerabilities", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to insert ignored vulnerabilities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"inserted": inserted})
}

func apiDeleteIgnoresHandler(w http.ResponseWriter, r *http.Request) {
	var req ignoresMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Logger.Error("failed to decode ignores DELETE body", "error", err)
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Repository == "" || req.Tag == "" || len(req.CVEIDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "missing required fields (repository, tag, cve_ids)")
		return
	}
	registry := req.Registry
	if registry == "" {
		registry = "index.docker.io"
	}
	deleted, err := db.BulkDeleteIgnoredImageVulnerabilities(registry, req.Repository, req.Tag, req.CVEIDs)
	if err != nil {
		log.Logger.Error("failed to delete ignored vulnerabilities", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to delete ignored vulnerabilities")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": deleted})
}

func apiComplianceReportHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: id")
		return
	}
	var severity *string
	if q.Get("severity") != "" {
		s := q.Get("severity")
		severity = &s
	}

	data, err := source.GetComplianceReportList(q.Get("cluster"))
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list compliance reports")
		return
	}
	report, found := complianceview.GetSingleReportData(data, id, severity)
	if !found {
		writeJSONError(w, http.StatusNotFound, "compliance report not found")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
