package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
	imageview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/image"
	roleview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/role"
)

var scrpr *scraper.WebScraper

// Start starts the webserver
func Start(port string, metricsURL string) error {
	// Create scraper
	scrp, err := scraper.NewWebScraper(metricsURL)
	if err != nil {
		return fmt.Errorf("encountered error creating new file scraper: %w", err)
	}
	scrpr = scrp

	mux := http.NewServeMux()
	mux.HandleFunc("/", imagesHandler)
	mux.HandleFunc("/image", imageHandler)
	mux.HandleFunc("/roles", rolesHandler)
	mux.Handle("/static/", http.FileServer(http.FS(content.Static)))
	return http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}

func imagesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/images.html"))
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
	imageData := imageview.GetImagesView(data)

	err = tmpl.Execute(w, imageData)
	if err != nil {
		log.Logger.Error("encountered error executing images html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func imageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/image.html"))
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
	hasFix := q.Get("hasfix")
	resources := q.Get("resources")
	notResources := q.Get("notresources")

	// Get vulnerability reports
	data, err := kube.GetVulnerabilityReportList()
	if err != nil {
		log.Logger.Error("error getting VulnerabilityReports", "error", err.Error())
		return
	}
	imageData := imageview.GetImagesView(data)
	v, ok := imageData.Images[imageview.Image{
		Name:   imageName,
		Digest: imageDigest,
	}]
	if !ok {
		log.Logger.Error("image name and digest query params did not produce a valid result from scraped data", "image", imageName, "digest", imageDigest)
		http.NotFound(w, r)
		return
	}

	// Get vulnerability list that matches filters
	view := imageview.ImageVulnerabilityView{
		Name:               imageName,
		Digest:             imageDigest,
		OSFamily:           v.OSFamily,
		OSVersion:          v.OSVersion,
		OSEndOfServiceLife: v.OSEndOfServiceLife,
	}
	for id, vuln := range v.Vulnerabilities {
		// filter by severity in query param
		if severity != "" && !strings.EqualFold(severity, vuln.Severity) {
			continue
		}

		// Filter if no fix version if hasfix=true
		if strings.EqualFold(hasFix, "true") && vuln.FixedVersion == "" {
			continue
		}

		// Filter if a fix version if hasfix=false
		if strings.EqualFold(hasFix, "false") && vuln.FixedVersion != "" {
			continue
		}

		// Filter if vulnerability resource does not equal resource in resources list
		if resources != "" {
			filters := strings.Split(resources, ",")
			found := filterByList(filters, vuln.Resource)
			if !found {
				continue
			}
		}

		// Filter if vulnerability resource equals specified resource in the notresource list
		if notResources != "" {
			filters := strings.Split(notResources, ",")
			found := filterByList(filters, vuln.Resource)
			if found {
				continue
			}
		}

		// append to data list to pass to template
		view.Data = append(view.Data, imageview.ImageVulnerabilityData{
			ID:            id,
			Vulnerability: vuln,
		})
	}
	view = imageview.SortImageVulnerabilityView(view)

	err = tmpl.Execute(w, view)
	if err != nil {
		log.Logger.Error("encountered error executing image html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}

func filterByList(filters []string, item string) bool {
	var found bool
	for _, filter := range filters {
		if strings.EqualFold(filter, item) {
			found = true
			break
		}
	}
	return found
}

func rolesHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/roles.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing images html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get scrape data from exporter
	data, err := scrapeImageData(w)
	if err != nil {
		return
	}
	roles := roleview.GetRolesView(data)

	err = tmpl.Execute(w, roles)
	if err != nil {
		log.Logger.Error("encountered error executing images html template", "error", err)
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}
}
