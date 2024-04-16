package web

import (
	"net/http"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

func scrapeImageData(w http.ResponseWriter) (*scraper.ScrapeData, error) {
	data, err := scrpr.ScrapeWeb()
	if err != nil {
		log.Logger.Error("encountered error scraping file", "error", err.Error())
		http.Error(w, "Internal Server Error, check server logs", http.StatusInternalServerError)
		return nil, err
	}

	return data, nil
}
