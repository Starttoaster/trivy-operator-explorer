package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/views/images"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
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

	// Get scrape data from exporter
	data, err := scrapeImageData(w)
	if err != nil {
		return
	}
	imageData := images.GetImagesView(data)

	tmpl.Execute(w, imageData)
}

func imageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(content.Static, "static/image.html"))
	if tmpl == nil {
		log.Logger.Error("encountered error parsing image html template")
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return
	}

	// Get scrape data from exporter
	data, err := scrapeImageData(w)
	if err != nil {
		return
	}
	imageData := images.GetImagesView(data)

	// Parse URL query params
	q := r.URL.Query()

	// Check image query params -- 404 if not found in image data, or param not passed
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
	v, ok := imageData.Images[images.Image{
		Image:  imageName,
		Digest: imageDigest,
	}]
	if !ok {
		log.Logger.Error("image name and digest query params did not produce a valid result from scraped data", "image", imageName, "digest", imageDigest)
		http.NotFound(w, r)
		return
	}

	// Check severity query param if it exists
	severity := q.Get("severity")

	// Get vulnerability list that matches severity, if specified
	view := images.ImageVulnerabilityView{
		Image:  imageName,
		Digest: imageDigest,
	}
	for id, vuln := range v.Vulnerabilities {
		// filter by severity in query param
		if severity != "" && !strings.EqualFold(severity, vuln.Severity) {
			continue
		}

		// append to data list to pass to template
		view.Data = append(view.Data, images.ImageVulnerabilityData{
			ID: id,
			Vulnerability: images.Vulnerability{
				Severity:          vuln.Severity,
				Score:             vuln.Score,
				Resource:          vuln.Resource,
				Title:             vuln.Title,
				VulnerableVersion: vuln.VulnerableVersion,
				FixedVersion:      vuln.FixedVersion,
			},
		})
	}
	view = images.SortImageVulnerabilityView(view)

	tmpl.Execute(w, view)
}
