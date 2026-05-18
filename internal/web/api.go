package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
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

	vulnerabilityData, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerability reports")
		return
	}
	imagesView := imagesview.GetView(vulnerabilityData, nil, imagesview.Filters{})

	complianceData, err := kube.GetComplianceReportList()
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

	data, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list vulnerability reports")
		return
	}
	imagesMap, err := kube.GetContainerImagesMap()
	if err != nil {
		log.Logger.Error("error getting a list of running images", "error", err.Error())
	}

	view := imagesview.GetView(data, imagesMap, imagesview.Filters{
		HasFix:      hasFixBool,
		ShowIgnored: showIgnoredBool,
	})
	writeJSON(w, http.StatusOK, view)
}

func apiImageHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	imageRepository := q.Get("repository")
	if imageRepository == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: repository")
		return
	}
	imageTag := q.Get("tag")
	imageDigest := q.Get("digest")
	if imageDigest == "" {
		writeJSONError(w, http.StatusBadRequest, "missing required query parameter: digest")
		return
	}
	imageRegistry := q.Get("registry")
	if imageRegistry == "" {
		imageRegistry = "index.docker.io"
	}
	severity := q.Get("severity")
	resources := q.Get("resources")
	hasFixBool := parseBoolQuery("hasfix", q.Get("hasfix"))
	showIgnoredBool := parseBoolQuery("showignored", q.Get("showignored"))

	reports, err := kube.GetVulnerabilityReportList()
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
		Resources:   strings.Split(resources, ","),
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

	reports, err := kube.GetRbacAssessmentReportList()
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

	reports, err := kube.GetRbacAssessmentReportList()
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
	reports, err := kube.GetClusterRbacAssessmentReportList()
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

	reports, err := kube.GetClusterRbacAssessmentReportList()
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

	reports, err := kube.GetConfigAuditReportList()
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

	reports, err := kube.GetConfigAuditReportList()
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
	reports, err := kube.GetClusterInfraAssessmentReportList()
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

	reports, err := kube.GetClusterInfraAssessmentReportList()
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
	data, err := kube.GetExposedSecretReportList()
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

	data, err := kube.GetExposedSecretReportList()
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
	data, err := kube.GetComplianceReportList()
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list compliance reports")
		return
	}
	writeJSON(w, http.StatusOK, complianceview.GetView(data))
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

	data, err := kube.GetComplianceReportList()
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		writeJSONError(w, http.StatusInternalServerError, "failed to list compliance reports")
		return
	}
	writeJSON(w, http.StatusOK, complianceview.GetSingleReportData(data, id, severity))
}
