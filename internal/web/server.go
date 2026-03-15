package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
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
	mux.HandleFunc("/ignore/bulk", bulkIgnoreHandler)
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
	mux.Handle("/static/", http.FileServer(http.FS(content.Static)))
	return http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}

// --- helpers to build views from DB ---

func buildImagesView(showIgnored, hasFix bool) imagesview.View {
	imageRows, err := db.GetAllImagesWithResources()
	if err != nil {
		log.Logger.Error("error getting images from DB", "error", err.Error())
		return nil
	}

	iMap := make(map[int]*imagesview.Data)
	for _, row := range imageRows {
		d, ok := iMap[row.ID]
		if !ok {
			d = &imagesview.Data{
				Registry:  row.Registry,
				Name:      row.Repository,
				Tag:       row.Tag,
				Digest:    row.Digest,
				OSFamily:  row.OSFamily,
				OSVersion: row.OSVersion,
				Resources: make(map[imagesview.ResourceMetadata]struct{}),
			}
			if row.OSEOSL {
				d.OSEndOfServiceLife = "true"
			}
			iMap[row.ID] = d
		}
		d.Resources[imagesview.ResourceMetadata{
			ClusterName: row.ClusterName,
			Kind:        row.ResourceKind,
			Name:        row.ResourceName,
			Namespace:   row.ResourceNamespace,
		}] = struct{}{}
	}

	allVulns, err := db.GetAllVulnerabilitySummary()
	if err != nil {
		log.Logger.Error("error getting vulnerabilities from DB", "error", err.Error())
	}

	for _, v := range allVulns {
		d, ok := iMap[v.ImageID]
		if !ok {
			continue
		}

		if !showIgnored {
			img := iMap[v.ImageID]
			ignoredCVEs, err := db.GetIgnoredCVEsForImage(img.Registry, img.Name, img.Tag)
			if err == nil {
				if _, isIgnored := ignoredCVEs[v.CVEID]; isIgnored {
					continue
				}
			}
		}

		if hasFix && strings.TrimSpace(v.FixedVersion) == "" {
			continue
		}

		vuln := imagesview.Vulnerability{
			ID:                v.CVEID,
			Severity:          v.Severity,
			Score:             v.Score,
			URL:               v.URL,
			Resource:          v.Resource,
			Title:             v.Title,
			VulnerableVersion: v.InstalledVersion,
			FixedVersion:      v.FixedVersion,
		}

		if v.FixedVersion == "" {
			d.NoFixAvailableCount++
		} else {
			d.FixAvailableCount++
		}

		switch strings.ToLower(v.Severity) {
		case "critical":
			d.CriticalVulnerabilities = append(d.CriticalVulnerabilities, vuln)
		case "high":
			d.HighVulnerabilities = append(d.HighVulnerabilities, vuln)
		case "medium":
			d.MediumVulnerabilities = append(d.MediumVulnerabilities, vuln)
		case "low":
			d.LowVulnerabilities = append(d.LowVulnerabilities, vuln)
		}
	}

	var view imagesview.View
	for _, d := range iMap {
		view = append(view, *d)
	}
	return view
}

func buildConfigAuditsView(namespace, kind string) configauditsview.View {
	reports, err := db.GetAllConfigAuditReports()
	if err != nil {
		log.Logger.Error("error getting config audit reports from DB", "error", err.Error())
		return nil
	}

	var view configauditsview.View
	for _, r := range reports {
		if namespace != "" && r.Namespace != namespace {
			continue
		}
		if kind != "" && r.Kind != kind {
			continue
		}

		checks, err := db.GetConfigAuditChecks(r.ID)
		if err != nil {
			log.Logger.Error("error getting config audit checks", "error", err.Error())
			continue
		}

		d := configauditsview.Data{
			ClusterName: r.ClusterName,
			Name:        r.Name,
			Namespace:   r.Namespace,
			Kind:        r.Kind,
		}

		for _, c := range checks {
			v := configauditsview.Vulnerability{
				ID:          c.CheckID,
				Title:       c.Title,
				Description: c.Description,
			}
			switch strings.ToLower(c.Severity) {
			case "critical":
				d.CriticalVulnerabilities = append(d.CriticalVulnerabilities, v)
			case "high":
				d.HighVulnerabilities = append(d.HighVulnerabilities, v)
			case "medium":
				d.MediumVulnerabilities = append(d.MediumVulnerabilities, v)
			case "low":
				d.LowVulnerabilities = append(d.LowVulnerabilities, v)
			}
		}
		view = append(view, d)
	}
	return view
}

func buildClusterAuditsView() clusterauditsview.View {
	reports, err := db.GetAllClusterInfraAuditReports()
	if err != nil {
		log.Logger.Error("error getting cluster infra audit reports from DB", "error", err.Error())
		return nil
	}

	var view clusterauditsview.View
	for _, r := range reports {
		checks, err := db.GetClusterInfraAuditChecks(r.ID)
		if err != nil {
			log.Logger.Error("error getting cluster infra audit checks", "error", err.Error())
			continue
		}

		d := clusterauditsview.Data{
			ClusterName: r.ClusterName,
			Name:        r.Name,
			Kind:        r.Kind,
		}

		for _, c := range checks {
			check := clusterauditsview.Check{
				ID:          c.CheckID,
				Title:       c.Title,
				Description: c.Description,
			}
			switch strings.ToLower(c.Severity) {
			case "critical":
				d.CriticalChecks = append(d.CriticalChecks, check)
			case "high":
				d.HighChecks = append(d.HighChecks, check)
			case "medium":
				d.MediumChecks = append(d.MediumChecks, check)
			case "low":
				d.LowChecks = append(d.LowChecks, check)
			}
		}
		view = append(view, d)
	}
	return view
}

func buildRolesView(namespace string) rolesview.View {
	reports, err := db.GetAllRbacAssessmentReports()
	if err != nil {
		log.Logger.Error("error getting rbac assessment reports from DB", "error", err.Error())
		return nil
	}

	var view rolesview.View
	for _, r := range reports {
		if namespace != "" && r.Namespace != namespace {
			continue
		}

		checks, err := db.GetRbacAssessmentChecks(r.ID)
		if err != nil {
			log.Logger.Error("error getting rbac assessment checks", "error", err.Error())
			continue
		}

		d := rolesview.Data{
			ClusterName: r.ClusterName,
			Name:        r.Name,
			Namespace:   r.Namespace,
			Kind:        r.Kind,
		}

		for _, c := range checks {
			v := rolesview.Vulnerability{
				ID:          c.CheckID,
				Title:       c.Title,
				Description: c.Description,
			}
			switch strings.ToLower(c.Severity) {
			case "critical":
				d.CriticalVulnerabilities = append(d.CriticalVulnerabilities, v)
			case "high":
				d.HighVulnerabilities = append(d.HighVulnerabilities, v)
			case "medium":
				d.MediumVulnerabilities = append(d.MediumVulnerabilities, v)
			case "low":
				d.LowVulnerabilities = append(d.LowVulnerabilities, v)
			}
		}
		view = append(view, d)
	}
	return view
}

func buildClusterRolesView() clusterrolesview.View {
	reports, err := db.GetAllClusterRbacAssessmentReports()
	if err != nil {
		log.Logger.Error("error getting cluster rbac assessment reports from DB", "error", err.Error())
		return nil
	}

	var view clusterrolesview.View
	for _, r := range reports {
		checks, err := db.GetClusterRbacAssessmentChecks(r.ID)
		if err != nil {
			log.Logger.Error("error getting cluster rbac assessment checks", "error", err.Error())
			continue
		}

		d := clusterrolesview.Data{
			ClusterName: r.ClusterName,
			Name:        r.Name,
			Kind:        r.Kind,
		}

		for _, c := range checks {
			v := clusterrolesview.Vulnerability{
				ID:          c.CheckID,
				Title:       c.Title,
				Description: c.Description,
			}
			switch strings.ToLower(c.Severity) {
			case "critical":
				d.CriticalVulnerabilities = append(d.CriticalVulnerabilities, v)
			case "high":
				d.HighVulnerabilities = append(d.HighVulnerabilities, v)
			case "medium":
				d.MediumVulnerabilities = append(d.MediumVulnerabilities, v)
			case "low":
				d.LowVulnerabilities = append(d.LowVulnerabilities, v)
			}
		}
		view = append(view, d)
	}
	return view
}

func buildExposedSecretsView() exposedsecretsview.View {
	reports, err := db.GetAllExposedSecretReports()
	if err != nil {
		log.Logger.Error("error getting exposed secret reports from DB", "error", err.Error())
		return nil
	}

	var view exposedsecretsview.View
	for _, r := range reports {
		secrets, err := db.GetExposedSecrets(r.ID)
		if err != nil {
			log.Logger.Error("error getting exposed secrets", "error", err.Error())
			continue
		}

		d := exposedsecretsview.Data{
			Name:   r.ImageName,
			Digest: r.ImageDigest,
			Resources: map[exposedsecretsview.ResourceMetadata]struct{}{
				{
					ClusterName: r.ClusterName,
					Kind:        r.ResourceKind,
					Name:        r.ResourceName,
					Namespace:   r.ResourceNamespace,
				}: {},
			},
		}

		for _, s := range secrets {
			secret := exposedsecretsview.Secret{
				Severity: s.Severity,
				Title:    s.Title,
				Target:   s.Target,
				Match:    s.Match,
			}
			switch strings.ToLower(s.Severity) {
			case "critical":
				d.Critical = append(d.Critical, secret)
			case "high":
				d.High = append(d.High, secret)
			case "medium":
				d.Medium = append(d.Medium, secret)
			case "low":
				d.Low = append(d.Low, secret)
			}
		}
		view = append(view, d)
	}
	return view
}

func buildComplianceView() complianceview.View {
	reports, err := db.GetAllComplianceReports()
	if err != nil {
		log.Logger.Error("error getting compliance reports from DB", "error", err.Error())
		return nil
	}

	var view complianceview.View
	for _, r := range reports {
		checks, err := db.GetComplianceChecks(r.ID)
		if err != nil {
			log.Logger.Error("error getting compliance checks", "error", err.Error())
			continue
		}

		var critFail, highFail, medFail, lowFail, unknownFail int
		var viewChecks []complianceview.Check
		for _, c := range checks {
			checkIDs, _ := db.ParseCheckIDs(c.CheckIDs)
			var ids []complianceview.CheckID
			for _, cid := range checkIDs {
				ids = append(ids, complianceview.CheckID{ID: cid.ID, URL: cid.URL})
			}
			vc := complianceview.Check{
				IDNumber:    c.CheckID,
				ID:          ids,
				Name:        c.Name,
				Description: c.Description,
				Severity:    c.Severity,
				TotalFailed: c.TotalFailed,
			}
			viewChecks = append(viewChecks, vc)

			if c.TotalFailed != nil {
				switch strings.ToUpper(c.Severity) {
				case "CRITICAL":
					critFail += *c.TotalFailed
				case "HIGH":
					highFail += *c.TotalFailed
				case "MEDIUM":
					medFail += *c.TotalFailed
				case "LOW":
					lowFail += *c.TotalFailed
				default:
					unknownFail += *c.TotalFailed
				}
			}
		}

		view = append(view, complianceview.Data{
			ClusterName: r.ClusterName,
			ID:          r.ReportID,
			Title:       r.Title,
			Summary: complianceview.Summary{
				FailCount:         r.FailCount,
				PassCount:         r.PassCount,
				CriticalFailCount: critFail,
				HighFailCount:     highFail,
				MediumFailCount:   medFail,
				LowFailCount:      lowFail,
				UnknownFailCount:  unknownFail,
			},
			Checks: viewChecks,
		})
	}
	return view
}

// --- HTTP handlers ---

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/index.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing index html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	imagesView := buildImagesView(false, false)
	complianceView := buildComplianceView()
	indexData := indexview.GetView(imagesView, complianceView)

	if err := tmpl.Execute(w, indexData); err != nil {
		log.Logger.Error("encountered error executing index html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
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

	q := r.URL.Query()
	hasFixBool, _ := strconv.ParseBool(q.Get("hasfix"))
	showIgnoredBool, _ := strconv.ParseBool(q.Get("showignored"))

	imageData := buildImagesView(showIgnoredBool, hasFixBool)

	templateData := struct {
		PageRoute string
		Data      imagesview.View
	}{
		PageRoute: "images",
		Data:      imageData,
	}

	if err := tmpl.Execute(w, templateData); err != nil {
		log.Logger.Error("encountered error executing images html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func imageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/image.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing image html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	imageRepository := q.Get("repository")
	if imageRepository == "" {
		http.NotFound(w, r)
		return
	}
	imageTag := q.Get("tag")
	imageDigest := q.Get("digest")
	if imageDigest == "" {
		http.NotFound(w, r)
		return
	}
	imageRegistry := q.Get("registry")
	if imageRegistry == "" {
		imageRegistry = "index.docker.io"
	}
	severity := q.Get("severity")
	resources := q.Get("resources")
	hasFixBool, _ := strconv.ParseBool(q.Get("hasfix"))
	showIgnoredBool, _ := strconv.ParseBool(q.Get("showignored"))

	img, err := db.GetImageByRegistryRepoDigest(imageRegistry, imageRepository, imageDigest)
	if err != nil {
		log.Logger.Error("image not found in DB", "error", err.Error())
		http.NotFound(w, r)
		return
	}

	vulns, err := db.GetVulnerabilitiesForImage(img.ID)
	if err != nil {
		log.Logger.Error("error getting vulnerabilities", "error", err.Error())
	}

	ignoredCVEs, err := db.GetIgnoredCVEsForImage(imageRegistry, imageRepository, imageTag)
	if err != nil {
		log.Logger.Error("error getting ignored CVEs", "error", err.Error())
		ignoredCVEs = nil
	}

	resourceList := strings.Split(resources, ",")

	view := imageview.View(imageview.Data{
		Registry:   img.Registry,
		Repository: img.Repository,
		Tag:        img.Tag,
		Digest:     img.Digest,
		OSFamily:   img.OSFamily,
		OSVersion:  img.OSVersion,
	})
	if img.OSEOSL {
		view.OSEndOfServiceLife = "true"
	}

	for _, v := range vulns {
		if !showIgnoredBool && ignoredCVEs != nil {
			if _, isIgnored := ignoredCVEs[v.CVEID]; isIgnored {
				continue
			}
		}

		if severity != "" && !strings.EqualFold(v.Severity, severity) {
			continue
		}

		if hasFixBool && strings.TrimSpace(v.FixedVersion) == "" {
			continue
		}

		if resources != "" && len(resourceList) > 0 && resourceList[0] != "" {
			if v.Resource != "" {
				found := false
				for _, res := range resourceList {
					if strings.EqualFold(v.Resource, res) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
		}

		isIgnored := false
		ignoreReason := ""
		if ignoredCVEs != nil {
			if ign, ok := ignoredCVEs[v.CVEID]; ok {
				isIgnored = true
				ignoreReason = ign.Reason
			}
		}

		vuln := imageview.Vulnerability{
			ID:                v.CVEID,
			Severity:          v.Severity,
			Score:             v.Score,
			URL:               v.URL,
			Resource:          v.Resource,
			Title:             v.Title,
			VulnerableVersion: v.InstalledVersion,
			FixedVersion:      v.FixedVersion,
			IsIgnored:         isIgnored,
			IgnoreReason:      ignoreReason,
		}
		view.Vulnerabilities = append(view.Vulnerabilities, vuln)
	}

	templateData := struct {
		PageRoute string
		Data      imageview.View
	}{
		PageRoute: "image",
		Data:      view,
	}

	if err := tmpl.Execute(w, templateData); err != nil {
		log.Logger.Error("encountered error executing image html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func ignoreHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData db.IgnoredImageVulnerability
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Logger.Error("Failed to decode request", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if requestData.Repository == "" || requestData.Tag == "" || requestData.CVEID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if requestData.Registry == "" {
		requestData.Registry = "index.docker.io"
	}

	if r.Method == http.MethodPost {
		if requestData.Reason == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}
		if err := db.InsertIgnoredImageVulnerability(requestData); err != nil {
			log.Logger.Error("Failed to insert ignored vulnerability", "error", err)
			http.Error(w, "Failed to save ignore request", http.StatusInternalServerError)
			return
		}
	} else if r.Method == http.MethodDelete {
		if err := db.DeleteIgnoredImageVulnerability(requestData.Registry, requestData.Repository, requestData.Tag, requestData.CVEID); err != nil {
			log.Logger.Error("Failed to delete ignored vulnerability", "error", err)
			http.Error(w, "Failed to unignore CVE", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// BulkIgnoreRequest represents a bulk ignore request
type BulkIgnoreRequest struct {
	Registry   string   `json:"registry"`
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	CVEIDs     []string `json:"cve_ids"`
	Reason     string   `json:"reason"`
}

func bulkIgnoreHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData BulkIgnoreRequest
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Logger.Error("Failed to decode bulk ignore request", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if requestData.Repository == "" || requestData.Tag == "" || len(requestData.CVEIDs) == 0 || requestData.Reason == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	registry := requestData.Registry
	if registry == "" {
		registry = "index.docker.io"
	}

	if err := db.BulkInsertIgnoredImageVulnerabilities(registry, requestData.Repository, requestData.Tag, requestData.Reason, requestData.CVEIDs); err != nil {
		log.Logger.Error("Failed to bulk insert ignored vulnerabilities", "error", err)
		http.Error(w, "Failed to save bulk ignore request", http.StatusInternalServerError)
		return
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

	namespace := r.URL.Query().Get("namespace")
	roles := buildRolesView(namespace)

	if err := tmpl.Execute(w, roles); err != nil {
		log.Logger.Error("encountered error executing roles html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func roleHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/role.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing role html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	namespace := q.Get("namespace")
	if namespace == "" {
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	allRoles := buildRolesView("")
	var found bool
	var role roleview.View
	for _, rd := range allRoles {
		if rd.Name == name && rd.Namespace == namespace {
			found = true
			role = roleview.View(roleview.Data{
				Name:      rd.Name,
				Namespace: rd.Namespace,
				Kind:      rd.Kind,
			})

			addChecksFiltered := func(checks []rolesview.Vulnerability) {
				for _, c := range checks {
					v := roleview.Vulnerability{ID: c.ID, Title: c.Title, Description: c.Description}
					role.Vulnerabilities = append(role.Vulnerabilities, v)
				}
			}

			if severity == "" || strings.EqualFold(severity, "critical") {
				addChecksFiltered(rd.CriticalVulnerabilities)
			}
			if severity == "" || strings.EqualFold(severity, "high") {
				addChecksFiltered(rd.HighVulnerabilities)
			}
			if severity == "" || strings.EqualFold(severity, "medium") {
				addChecksFiltered(rd.MediumVulnerabilities)
			}
			if severity == "" || strings.EqualFold(severity, "low") {
				addChecksFiltered(rd.LowVulnerabilities)
			}
			break
		}
	}

	if !found {
		http.NotFound(w, r)
		return
	}

	if err := tmpl.Execute(w, role); err != nil {
		log.Logger.Error("encountered error executing role html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func clusterrolesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusterroles.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusterroles html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	roles := buildClusterRolesView()

	if err := tmpl.Execute(w, roles); err != nil {
		log.Logger.Error("encountered error executing clusterroles html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func clusterroleHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusterrole.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusterrole html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	severity := q.Get("severity")

	allRoles := buildClusterRolesView()
	var found bool
	var role clusterroleview.View
	for _, rd := range allRoles {
		if rd.Name == name {
			found = true
			role = clusterroleview.View(clusterroleview.Data{
				Name: rd.Name,
				Kind: rd.Kind,
			})

			addChecksFiltered := func(checks []clusterrolesview.Vulnerability) {
				for _, c := range checks {
					v := clusterroleview.Vulnerability{ID: c.ID, Title: c.Title, Description: c.Description}
					role.Vulnerabilities = append(role.Vulnerabilities, v)
				}
			}

			if severity == "" || strings.EqualFold(severity, "critical") {
				addChecksFiltered(rd.CriticalVulnerabilities)
			}
			if severity == "" || strings.EqualFold(severity, "high") {
				addChecksFiltered(rd.HighVulnerabilities)
			}
			if severity == "" || strings.EqualFold(severity, "medium") {
				addChecksFiltered(rd.MediumVulnerabilities)
			}
			if severity == "" || strings.EqualFold(severity, "low") {
				addChecksFiltered(rd.LowVulnerabilities)
			}
			break
		}
	}

	if !found {
		http.NotFound(w, r)
		return
	}

	if err := tmpl.Execute(w, role); err != nil {
		log.Logger.Error("encountered error executing clusterrole html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func configauditsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/configaudits.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing configaudits html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	audits := buildConfigAuditsView(q.Get("namespace"), q.Get("kind"))

	if err := tmpl.Execute(w, audits); err != nil {
		log.Logger.Error("encountered error executing configaudits html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func configauditHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/configaudit.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing configaudit html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	name := q.Get("name")
	namespace := q.Get("namespace")
	kind := q.Get("kind")
	severity := q.Get("severity")
	if name == "" || namespace == "" || kind == "" {
		http.NotFound(w, r)
		return
	}

	allAudits := buildConfigAuditsView("", "")
	var found bool
	var audit configauditview.View
	for _, ad := range allAudits {
		if ad.Name == name && ad.Namespace == namespace && ad.Kind == kind {
			found = true
			audit = configauditview.View(configauditview.Data{
				Name:      ad.Name,
				Namespace: ad.Namespace,
				Kind:      ad.Kind,
			})

			addChecks := func(checks []configauditsview.Vulnerability, sev string) {
				if severity != "" && !strings.EqualFold(severity, sev) {
					return
				}
				for _, c := range checks {
					audit.Vulnerabilities = append(audit.Vulnerabilities, configauditview.Vulnerability{
						ID: c.ID, Severity: sev, Title: c.Title, Description: c.Description,
					})
				}
			}
			addChecks(ad.CriticalVulnerabilities, "CRITICAL")
			addChecks(ad.HighVulnerabilities, "HIGH")
			addChecks(ad.MediumVulnerabilities, "MEDIUM")
			addChecks(ad.LowVulnerabilities, "LOW")
			break
		}
	}

	if !found {
		http.NotFound(w, r)
		return
	}

	if err := tmpl.Execute(w, audit); err != nil {
		log.Logger.Error("encountered error executing configaudit html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func clusterauditsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusteraudits.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusteraudits html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	audits := buildClusterAuditsView()

	if err := tmpl.Execute(w, audits); err != nil {
		log.Logger.Error("encountered error executing clusteraudits html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func clusterauditHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/clusteraudit.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing clusteraudit html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	name := q.Get("name")
	kind := q.Get("kind")
	severity := q.Get("severity")
	if name == "" || kind == "" {
		http.NotFound(w, r)
		return
	}

	allAudits := buildClusterAuditsView()
	var found bool
	var audit clusterauditview.View
	for _, ad := range allAudits {
		if ad.Name == name && ad.Kind == kind {
			found = true
			audit = clusterauditview.View(clusterauditview.Data{
				Name: ad.Name,
				Kind: ad.Kind,
			})

			addChecks := func(checks []clusterauditsview.Check, sev string) {
				if severity != "" && !strings.EqualFold(severity, sev) {
					return
				}
				for _, c := range checks {
					audit.Checks = append(audit.Checks, clusterauditview.Check{
						ID: c.ID, Severity: sev, Title: c.Title, Description: c.Description,
					})
				}
			}
			addChecks(ad.CriticalChecks, "CRITICAL")
			addChecks(ad.HighChecks, "HIGH")
			addChecks(ad.MediumChecks, "MEDIUM")
			addChecks(ad.LowChecks, "LOW")
			break
		}
	}

	if !found {
		http.NotFound(w, r)
		return
	}

	if err := tmpl.Execute(w, audit); err != nil {
		log.Logger.Error("encountered error executing clusteraudit html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func exposedsecretsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/exposedsecrets.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing exposed secrets html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	imageData := buildExposedSecretsView()

	if err := tmpl.Execute(w, imageData); err != nil {
		log.Logger.Error("encountered error executing exposed secrets html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func exposedsecretHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/exposedsecret.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing exposed secret html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	imageName := q.Get("image")
	imageDigest := q.Get("digest")
	severity := q.Get("severity")
	if imageName == "" || imageDigest == "" {
		http.NotFound(w, r)
		return
	}

	allSecrets := buildExposedSecretsView()
	var found bool
	var view exposedsecretview.View
	for _, sd := range allSecrets {
		if sd.Name == imageName && sd.Digest == imageDigest {
			found = true
			view = exposedsecretview.View(exposedsecretview.Data{
				Name:   sd.Name,
				Digest: sd.Digest,
			})

			addSecrets := func(secrets []exposedsecretsview.Secret, sev string) {
				if severity != "" && !strings.EqualFold(severity, sev) {
					return
				}
				for _, s := range secrets {
					view.Secrets = append(view.Secrets, exposedsecretview.Secret{
						Severity: s.Severity, Title: s.Title, Target: s.Target, Match: s.Match,
					})
				}
			}
			addSecrets(sd.Critical, "CRITICAL")
			addSecrets(sd.High, "HIGH")
			addSecrets(sd.Medium, "MEDIUM")
			addSecrets(sd.Low, "LOW")
			break
		}
	}

	if !found {
		http.NotFound(w, r)
		return
	}

	if err := tmpl.Execute(w, view); err != nil {
		log.Logger.Error("encountered error executing exposed secret html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func complianceReportsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/compliancereports.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing compliance reports html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	complianceView := buildComplianceView()

	if err := tmpl.Execute(w, complianceView); err != nil {
		log.Logger.Error("encountered error executing compliance reports html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}

func complianceReportHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/compliancereport.html", "static/sidebar.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing compliance report html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	id := q.Get("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	var severity *string
	if s := q.Get("severity"); s != "" {
		severity = &s
	}

	allCompliance := buildComplianceView()
	var reportData complianceview.Data
	for _, c := range allCompliance {
		if c.ID == id {
			reportData = c
			if severity != nil {
				var filtered []complianceview.Check
				for _, check := range reportData.Checks {
					if strings.EqualFold(check.Severity, *severity) {
						if check.TotalFailed != nil && *check.TotalFailed > 0 {
							filtered = append(filtered, check)
						}
					}
				}
				reportData.Checks = filtered
			} else {
				var filtered []complianceview.Check
				for _, check := range reportData.Checks {
					if check.TotalFailed != nil && *check.TotalFailed > 0 {
						filtered = append(filtered, check)
					}
				}
				reportData.Checks = filtered
			}
			break
		}
	}

	if err := tmpl.Execute(w, reportData); err != nil {
		log.Logger.Error("encountered error executing compliance report html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
	}
}
