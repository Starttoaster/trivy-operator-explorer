package views

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/views"
)

// GetImagesView converts some scrape data to the /images view
func GetImagesView(data *scraper.ScrapeData) ImagesView {
	var i ImagesView
	i.Images = make(map[Image]ImageData)

	for _, gauge := range data.Gauges {
		if gauge.Key == views.TrivyImageVulnerabilityMetricName {
			// TODO -- grab each label into variables individually and check that they're not empty
			// Construct all data types from metric data
			image := Image{
				Name:   getImageNameFromLabels(gauge),
				Digest: gauge.Labels["image_digest"],
			}
			podData := PodMetadata{
				Pod:       gauge.Labels["resource_name"],
				Namespace: gauge.Labels["namespace"],
			}
			score := float32(0.0)
			if gauge.Labels["vuln_score"] != "" {
				scoreVar, err := strconv.ParseFloat(gauge.Labels["vuln_score"], 32)
				if err != nil {
					log.Logger.Error("could not convert string to float32",
						"error", err.Error(),
						"score", gauge.Labels["vuln_score"],
						"image", image.Name,
					)
					continue
				}
				score = float32(scoreVar)
			}
			cveID := gauge.Labels["vuln_id"]
			vuln := Vulnerability{
				Severity:          gauge.Labels["severity"],
				Score:             float32(score),
				Resource:          gauge.Labels["resource"],
				Title:             gauge.Labels["vuln_title"],
				VulnerableVersion: gauge.Labels["installed_version"],
				FixedVersion:      gauge.Labels["fixed_version"],
			}

			// Check if this image is already in the map
			_, ok := i.Images[image]
			if ok {
				// Add to the image's vulnerability list if it hasn't been yet
				_, ok := i.Images[image].Vulnerabilities[cveID]
				if !ok {
					i.Images[image].Vulnerabilities[cveID] = vuln
				}

				// Add to the list of Pods using this image if it hasn't been yet
				_, ok = i.Images[image].Pods[podData]
				if !ok {
					i.Images[image].Pods[podData] = struct{}{}
				}
			} else {
				podMap := make(map[PodMetadata]struct{})
				vulnMap := make(map[string]Vulnerability)
				imageData := ImageData{
					Name:            image.Name,
					Digest:          image.Digest,
					Vulnerabilities: vulnMap,
					Pods:            podMap,
				}
				imageData.Vulnerabilities[cveID] = vuln
				imageData.Pods[podData] = struct{}{}
				i.Images[image] = imageData
			}
		}
	}

	for _, gauge := range data.Gauges {
		if gauge.Key == views.TrivyImageInfoMetricName {
			image := Image{
				Name:   getImageNameFromLabels(gauge),
				Digest: gauge.Labels["image_digest"],
			}

			if data, ok := i.Images[image]; ok {
				data.OSFamily = gauge.Labels["image_os_family"]
				data.OSVersion = gauge.Labels["image_os_name"]
				data.OSEndOfServiceLife = gauge.Labels["image_os_eosl"]
				i.Images[image] = data
			}
		}
	}

	i = setImagesViewVulnerabilityCounters(i)
	i = sortImagesView(i)

	return i
}

func setImagesViewVulnerabilityCounters(i ImagesView) ImagesView {
	for k, v := range i.Images {
		for _, vuln := range v.Vulnerabilities {
			switch vuln.Severity {
			case "Critical":
				v.CriticalVulnerabilities++
			case "High":
				v.HighVulnerabilities++
			case "Medium":
				v.MediumVulnerabilities++
			case "Low":
				v.LowVulnerabilities++
			}
			i.Images[k] = v
		}
	}
	return i
}

func sortImagesView(i ImagesView) ImagesView {
	for _, v := range i.Images {
		i.SortedImages = append(i.SortedImages, v)
	}

	// Sort the slice by severity in descending order
	sort.Slice(i.SortedImages, func(j, k int) bool {
		if i.SortedImages[j].CriticalVulnerabilities != i.SortedImages[k].CriticalVulnerabilities {
			return i.SortedImages[j].CriticalVulnerabilities > i.SortedImages[k].CriticalVulnerabilities
		}

		if i.SortedImages[j].HighVulnerabilities != i.SortedImages[k].HighVulnerabilities {
			return i.SortedImages[j].HighVulnerabilities > i.SortedImages[k].HighVulnerabilities
		}

		if i.SortedImages[j].MediumVulnerabilities != i.SortedImages[k].MediumVulnerabilities {
			return i.SortedImages[j].MediumVulnerabilities > i.SortedImages[k].MediumVulnerabilities
		}

		return i.SortedImages[j].LowVulnerabilities > i.SortedImages[k].LowVulnerabilities
	})

	return i
}

func getImageNameFromLabels(gauge scraper.PrometheusGaugeMetric) string {
	if gauge.Labels["image_registry"] == "index.docker.io" {
		// If Docker Hub, trim the registry prefix for readability
		// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(gauge.Labels["image_repository"], "library/"), gauge.Labels["image_tag"])
	}
	return fmt.Sprintf("%s/%s:%s", gauge.Labels["image_registry"], gauge.Labels["image_repository"], gauge.Labels["image_tag"])
}
