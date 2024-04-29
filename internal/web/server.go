package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
	clusterroleview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/clusterrole"
	clusterrolesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/clusterroles"
	configauditview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/configaudit"
	configauditsview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/configaudits"
	imageview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/image"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
	roleview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/role"
	rolesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/roles"
)

// Start starts the webserver
func Start(port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", imagesHandler)
	mux.HandleFunc("/image", imageHandler)
	mux.HandleFunc("/roles", rolesHandler)
	mux.HandleFunc("/role", roleHandler)
	mux.HandleFunc("/clusterroles", clusterrolesHandler)
	mux.HandleFunc("/clusterrole", clusterroleHandler)
	mux.HandleFunc("/configaudits", configauditsHandler)
	mux.HandleFunc("/configaudit", configauditHandler)
	mux.Handle("/static/", http.FileServer(http.FS(content.Static)))
	return http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}

func imagesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/images.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing images html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get vulnerability reports
	data, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}
	imageData := imagesview.GetView(data)

	err = tmpl.Execute(w, imageData)
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
	resources := q.Get("resources")
	notResources := q.Get("notresources")

	hasFix := q.Get("hasfix")
	var hasFixBool bool
	if hasFix != "" {
		var err error
		hasFixBool, err = strconv.ParseBool(hasFix)
		if err != nil {
			log.Logger.Warn("could not parse hasfix query parameter to bool type, ignoring filter", "raw", hasFix, "error", err.Error())
		}
	}

	// Get vulnerability reports
	reports, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}

	// Get image view from reports
	view, found := imageview.GetView(reports, imageview.Filters{
		Name:         imageName,
		Digest:       imageDigest,
		Severity:     severity,
		HasFix:       hasFixBool,
		Resources:    strings.Split(resources, ","),
		NotResources: strings.Split(notResources, ","),
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
		log.Logger.Error("encountered error executing image html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func rolesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/roles.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing roles html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get role reports
	reports, err := kube.GetRbacAssessmentReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}
	roles := rolesview.GetView(reports)

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

	// Get reports
	reports, err := kube.GetConfigAuditReportList()
	if err != nil {
		log.Logger.Error("error getting configauditreports", "error", err.Error())
		return
	}
	audits := configauditsview.GetView(reports)

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
