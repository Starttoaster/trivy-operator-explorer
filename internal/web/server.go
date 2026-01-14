package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/utils"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
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

// Start starts the webserver
func Start(port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/images", imagesHandler)
	mux.HandleFunc("/image", imageHandler)
	mux.HandleFunc("/ignore", ignoreHandler)
	mux.HandleFunc("/configaudits", configauditsHandler)
	mux.HandleFunc("/configaudit", configauditHandler)
	mux.HandleFunc("/clusteraudits", clusterauditsHandler)
	mux.HandleFunc("/clusteraudit", clusterauditHandler)
	mux.HandleFunc("/clusterroles", clusterrolesHandler)
	mux.HandleFunc("/clusterrole", clusterroleHandler)
	mux.HandleFunc("/exposedsecrets", exposedsecretsHandler)
	mux.HandleFunc("/exposedsecret", exposedsecretHandler)
	mux.HandleFunc("/roles", rolesHandler)
	mux.HandleFunc("/role", roleHandler)
	mux.HandleFunc("/compliancereports", complianceReportsHandler)
	mux.HandleFunc("/compliancereport", complianceReportHandler)
	// TODO just serve the js and css directories in static
	// this serves the html templates for no reason
	mux.Handle("/static/", http.FileServer(http.FS(content.Static)))
	return http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/index.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing index html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get vulnerability reports
	vulnerabilityData, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}
	imagesView := imagesview.GetView(vulnerabilityData, nil, imagesview.Filters{})

	// Get compliance reports
	complianceData, err := kube.GetComplianceReportList()
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		return
	}
	complianceView := complianceview.GetView(complianceData)

	// Get index view
	indexData := indexview.GetView(imagesView, complianceView)

	err = tmpl.Execute(w, indexData)
	if err != nil {
		log.Logger.Error("encountered error executing index html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func imagesHandler(w http.ResponseWriter, r *http.Request) {
	funcMap := template.FuncMap{
		"sanitizeID": func(s string) string {
			replacer := strings.NewReplacer("/", "_", ":", "_", " ", "_", "-", "_", ".", "_")
			return replacer.Replace(s)
		},
	}

	tmpl := template.Must(template.New("images.html").Funcs(funcMap).ParseFS(content.Static, "static/images.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing images html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params
	hasFix := q.Get("hasfix")
	var hasFixBool bool
	if hasFix != "" {
		var err error
		hasFixBool, err = strconv.ParseBool(hasFix)
		if err != nil {
			log.Logger.Warn("could not parse hasfix query parameter to bool type, ignoring filter", "raw", hasFix, "error", err.Error())
		}
	}

	showIgnored := q.Get("showignored")
	var showIgnoredBool bool
	if showIgnored != "" {
		var err error
		showIgnoredBool, err = strconv.ParseBool(showIgnored)
		if err != nil {
			log.Logger.Warn("could not parse showignored query parameter to bool type, ignoring filter", "raw", showIgnored, "error", err.Error())
		}
	}

	// Get vulnerability reports
	data, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}
	// Get total images map -- we don't return here if we get an error because it's for optional helpful data
	imagesMap, err := kube.GetContainerImagesMap()
	if err != nil {
		log.Logger.Error("error getting a list of running images", "error", err.Error())
	}

	imageData := imagesview.GetView(data, imagesMap, imagesview.Filters{
		HasFix:      hasFixBool,
		ShowIgnored: showIgnoredBool,
	})

	// Add page type to template data
	templateData := struct {
		PageRoute string
		Data      imagesview.View
	}{
		PageRoute: "images",
		Data:      imageData,
	}

	err = tmpl.Execute(w, templateData)
	if err != nil {
		log.Logger.Error("encountered error executing images html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func imageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/image.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing image html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	imageRepository := q.Get("repository")
	if imageRepository == "" {
		log.Logger.Error("image repository query param missing from request")
		http.NotFound(w, r)
		return
	}
	imageTag := q.Get("tag")
	if imageTag == "" {
		log.Logger.Error("image tag query param missing from request")
		http.NotFound(w, r)
		return
	}
	imageDigest := q.Get("digest")
	if imageDigest == "" {
		log.Logger.Error("image digest query param missing from request")
		http.NotFound(w, r)
		return
	}
	imageRegistry := q.Get("registry")
	if imageRegistry == "" {
		imageRegistry = "index.docker.io"
	}
	severity := q.Get("severity")
	resources := q.Get("resources")

	hasFix := q.Get("hasfix")
	var hasFixBool bool
	if hasFix != "" {
		var err error
		hasFixBool, err = strconv.ParseBool(hasFix)
		if err != nil {
			log.Logger.Warn("could not parse hasfix query parameter to bool type, ignoring filter", "raw", hasFix, "error", err.Error())
		}
	}

	showIgnored := q.Get("showignored")
	var showIgnoredBool bool
	if showIgnored != "" {
		var err error
		showIgnoredBool, err = strconv.ParseBool(showIgnored)
		if err != nil {
			log.Logger.Warn("could not parse showignored query parameter to bool type, ignoring filter", "raw", showIgnored, "error", err.Error())
		}
	}

	// Get vulnerability reports
	reports, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}

	// Get ignored CVEs from database
	ignoredCVEs, err := db.GetIgnoredCVEsForImage(imageRegistry, imageRepository, imageTag)
	if err != nil {
		log.Logger.Error("error getting ignored CVEs", "error", err.Error())
		// Continue without ignored CVEs rather than failing the request
		ignoredCVEs = nil
	}

	imageName := utils.AssembleImageFullName(utils.FormatPrettyImageRegistry(imageRegistry), utils.FormatPrettyImageRepo(imageRepository), imageTag)

	// Get image view from reports
	view, found := imageview.GetView(reports, imageview.Filters{
		Name:        imageName,
		Digest:      imageDigest,
		Severity:    severity,
		HasFix:      hasFixBool,
		ShowIgnored: showIgnoredBool,
		Resources:   strings.Split(resources, ","),
	}, ignoredCVEs)

	// If the selected image from query params was not found, 404
	if !found {
		log.Logger.Error("image name and digest query params did not produce a valid result from scraped data", "image", imageName, "digest", imageDigest)
		http.NotFound(w, r)
		return
	}

	// Add page type to template data
	templateData := struct {
		PageRoute string
		Data      imageview.View
	}{
		PageRoute: "image",
		Data:      view,
	}

	// Execute html template
	err = tmpl.Execute(w, templateData)
	if err != nil {
		log.Logger.Error("encountered error executing image html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func ignoreHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON request body for unignore
	var requestData db.IgnoredImageVulnerability
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Logger.Error("Failed to decode unignore request", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate always required fields
	if requestData.Repository == "" || requestData.Tag == "" || requestData.CVEID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Set default registry for Docker Hub if empty
	if requestData.Registry == "" {
		requestData.Registry = "index.docker.io"
	}

	// Handle both POST (ignore) and DELETE (unignore) requests
	if r.Method == http.MethodPost {
		// Validate additional required fields
		if requestData.Reason == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		// Insert into database
		if err := db.InsertIgnoredImageVulnerability(requestData); err != nil {
			log.Logger.Error("Failed to insert ignored vulnerability", "error", err)
			http.Error(w, "Failed to save ignore request", http.StatusInternalServerError)
			return
		}

	} else if r.Method == http.MethodDelete {
		// Delete from database
		if err := db.DeleteIgnoredImageVulnerability(requestData.Registry, requestData.Repository, requestData.Tag, requestData.CVEID); err != nil {
			log.Logger.Error("Failed to delete ignored vulnerability", "error", err)
			http.Error(w, "Failed to unignore CVE", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func rolesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/roles.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing roles html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params
	namespace := q.Get("namespace")

	// Get role reports
	reports, err := kube.GetRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}
	roles := rolesview.GetView(reports, rolesview.Filters{
		Namespace: namespace,
	})

	err = tmpl.Execute(w, roles)
	if err != nil {
		log.Logger.Error("encountered error executing roles html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func roleHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/role.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing role html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	name := q.Get("name")
	if name == "" {
		log.Logger.Error("role name query param missing from request")
		http.NotFound(w, r)
		return
	}
	namespace := q.Get("namespace")
	if namespace == "" {
		log.Logger.Error("role namespace query param missing from request")
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	// Get role reports
	reports, err := kube.GetRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting RBACAssessmentReports", "error", err.Error())
		return
	}
	role, found := roleview.GetView(reports, roleview.Filters{
		Name:      name,
		Namespace: namespace,
		Severity:  severity,
	})

	// If the selected role from query params was not found, 404
	if !found {
		log.Logger.Error("role name and namespace query params did not produce a valid result from reports", "name", name, "namespace", namespace)
		http.NotFound(w, r)
		return
	}

	err = tmpl.Execute(w, role)
	if err != nil {
		log.Logger.Error("encountered error executing role html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func clusterrolesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusterroles.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing roles html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get role reports
	reports, err := kube.GetClusterRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting clusterrbacassessmentreports", "error", err.Error())
		return
	}
	roles := clusterrolesview.GetView(reports)

	err = tmpl.Execute(w, roles)
	if err != nil {
		log.Logger.Error("encountered error executing roles html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func clusterroleHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusterrole.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusterrole html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	name := q.Get("name")
	if name == "" {
		log.Logger.Error("role name query param missing from request")
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	// Get clusterrole reports
	reports, err := kube.GetClusterRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting clusterrbacassessmentreports", "error", err.Error())
		return
	}
	role, found := clusterroleview.GetView(reports, clusterroleview.Filters{
		Name:     name,
		Severity: severity,
	})

	// If the selected clusterrole from query params was not found, 404
	if !found {
		log.Logger.Error("clusterrole name query params did not produce a valid result from reports", "name", name)
		http.NotFound(w, r)
		return
	}

	err = tmpl.Execute(w, role)
	if err != nil {
		log.Logger.Error("encountered error executing clusterrole html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func configauditsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/configaudits.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing configaudits html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params
	namespace := q.Get("namespace")
	kind := q.Get("kind")

	// Get reports
	reports, err := kube.GetConfigAuditReportList()
	if err != nil {
		log.Logger.Error("error getting configauditreports", "error", err.Error())
		return
	}
	audits := configauditsview.GetView(reports, configauditsview.Filters{
		Namespace: namespace,
		Kind:      kind,
	})

	err = tmpl.Execute(w, audits)
	if err != nil {
		log.Logger.Error("encountered error executing configaudits html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func configauditHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/configaudit.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing configaudit html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	name := q.Get("name")
	if name == "" {
		log.Logger.Error("config audit name query param missing from request")
		http.NotFound(w, r)
		return
	}
	namespace := q.Get("namespace")
	if namespace == "" {
		log.Logger.Error("config audit namespace query param missing from request")
		http.NotFound(w, r)
		return
	}
	kind := q.Get("kind")
	if kind == "" {
		log.Logger.Error("config audit kind query param missing from request")
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	// Get configaudit reports
	reports, err := kube.GetConfigAuditReportList()
	if err != nil {
		log.Logger.Error("error getting configauditreports", "error", err.Error())
		return
	}
	audit, found := configauditview.GetView(reports, configauditview.Filters{
		Name:      name,
		Namespace: namespace,
		Kind:      kind,
		Severity:  severity,
	})

	// If the selected resource from query params was not found, 404
	if !found {
		log.Logger.Error("resource name and namespace query params did not produce a valid result from reports", "name", name, "namespace", namespace)
		http.NotFound(w, r)
		return
	}

	err = tmpl.Execute(w, audit)
	if err != nil {
		log.Logger.Error("encountered error executing configaudit html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func clusterauditsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusteraudits.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusteraudits html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get reports
	reports, err := kube.GetClusterInfraAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting clusterinfraassessmentreports", "error", err.Error())
		return
	}
	audits := clusterauditsview.GetView(reports)

	err = tmpl.Execute(w, audits)
	if err != nil {
		log.Logger.Error("encountered error executing clusteraudits html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func clusterauditHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusteraudit.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusteraudit html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	name := q.Get("name")
	if name == "" {
		log.Logger.Error("cluster audit name query param missing from request")
		http.NotFound(w, r)
		return
	}
	kind := q.Get("kind")
	if kind == "" {
		log.Logger.Error("cluster audit kind query param missing from request")
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	// Get clusteraudit reports
	reports, err := kube.GetClusterInfraAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting clusterinfraassessmentreports", "error", err.Error())
		return
	}
	audit, found := clusterauditview.GetView(reports, clusterauditview.Filters{
		Name:     name,
		Kind:     kind,
		Severity: severity,
	})

	// If the selected resource from query params was not found, 404
	if !found {
		log.Logger.Error("resource name query params did not produce a valid result from reports", "name", name)
		http.NotFound(w, r)
		return
	}

	err = tmpl.Execute(w, audit)
	if err != nil {
		log.Logger.Error("encountered error executing clusteraudit html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func exposedsecretsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/exposedsecrets.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing exposed secrets html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	data, err := kube.GetExposedSecretReportList()
	if err != nil {
		log.Logger.Error("error getting ExposedSecretReports", "error", err.Error())
		return
	}
	imageData := exposedsecretsview.GetView(data)

	err = tmpl.Execute(w, imageData)
	if err != nil {
		log.Logger.Error("encountered error executing exposed secrets html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func exposedsecretHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/exposedsecret.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing exposed secret html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	imageName := q.Get("image")
	if imageName == "" {
		log.Logger.Error("image name query param missing from request")
		http.NotFound(w, r)
		return
	}
	imageDigest := q.Get("digest")
	if imageDigest == "" {
		log.Logger.Error("image digest query param missing from request")
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	// Get secret reports
	data, err := kube.GetExposedSecretReportList()
	if err != nil {
		log.Logger.Error("error getting ExposedSecretReports", "error", err.Error())
		return
	}

	// Get image view from reports
	view, found := exposedsecretview.GetView(data, exposedsecretview.Filters{
		Name:     imageName,
		Digest:   imageDigest,
		Severity: severity,
	})

	// If the selected image from query params was not found, 404
	if !found {
		log.Logger.Error("image name and digest query params did not produce a valid result from scraped data", "image", imageName, "digest", imageDigest)
		http.NotFound(w, r)
		return
	}

	// Execute html template
	err = tmpl.Execute(w, view)
	if err != nil {
		log.Logger.Error("encountered error executing exposed secret html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func complianceReportsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/compliancereports.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing compliance reports html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get compliance reports
	complianceData, err := kube.GetComplianceReportList()
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		return
	}
	complianceView := complianceview.GetView(complianceData)

	err = tmpl.Execute(w, complianceView)
	if err != nil {
		log.Logger.Error("encountered error executing compliance reports html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func complianceReportHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/compliancereport.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing compliance report html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Parse URL query params
	q := r.URL.Query()

	// Check query params -- 404 if required params not passed
	id := q.Get("id")
	if id == "" {
		log.Logger.Error("report id query param missing from request")
		http.NotFound(w, r)
		return
	}
	var severity *string
	if q.Get("severity") != "" {
		s := q.Get("severity")
		severity = &s
	}

	// Get compliance reports
	complianceData, err := kube.GetComplianceReportList()
	if err != nil {
		log.Logger.Error("error getting ComplianceReports", "error", err.Error())
		return
	}
	complianceView := complianceview.GetSingleReportData(complianceData, id, severity)

	err = tmpl.Execute(w, complianceView)
	if err != nil {
		log.Logger.Error("encountered error executing compliance report html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}
