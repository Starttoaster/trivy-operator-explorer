package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
	imageview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/image"
	imagesview "github.com/starttoaster/trivy-operator-explorer/internal/web/views/images"
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
	imageData := imagesview.GetImagesView(data)

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
	view, found := imageview.GetImageView(reports, imageview.ImageFilters{
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
