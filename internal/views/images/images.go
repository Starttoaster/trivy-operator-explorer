package images

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	scraper "github.com/starttoaster/prometheus-exporter-scraper"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

const TrivyImageVulnerabilityMetricName = "trivy_vulnerability_id"

func GetImagesView(data *scraper.ScrapeData) ImagesView {
	var i ImagesView
	i.Images = make(map[Image]ImageData)

	for _, gauge := range data.Gauges {
		if gauge.Key == TrivyImageVulnerabilityMetricName {
			// TODO -- grab each label into variables individually and check that they're not empty
			// Construct all data types from metric data
			var image Image
			if gauge.Labels["image_registry"] == "index.docker.io" {
				// If Docker Hub, trim the registry prefix for readability
				// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
				image.Image = fmt.Sprintf("%s:%s", strings.TrimPrefix(gauge.Labels["image_repository"], "library/"), gauge.Labels["image_tag"])
			} else {
				image.Image = fmt.Sprintf("%s/%s:%s", gauge.Labels["image_registry"], gauge.Labels["image_repository"], gauge.Labels["image_tag"])
			}
			image.Digest = gauge.Labels["image_digest"]
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
						"image", image.Image,
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
					Vulnerabilities: vulnMap,
					Pods:            podMap,
				}
				imageData.Vulnerabilities[cveID] = vuln
				imageData.Pods[podData] = struct{}{}
				i.Images[image] = imageData
			}
		}
	}

	i = setImagesViewVulnerabilityCounters(i)

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

// SortImageVulnerabilityView sorts the provided ImageVulnerabilityView's data slice
func SortImageVulnerabilityView(v ImageVulnerabilityView) ImageVulnerabilityView {
	// Sort by vulnerability severity separately
	// Because sometimes low or other tier vulnerabilities also have high scores
	var (
		crit []ImageVulnerabilityData
		high []ImageVulnerabilityData
		med  []ImageVulnerabilityData
		low  []ImageVulnerabilityData
	)
	for _, data := range v.Data {
		switch data.Severity {
		case "Critical":
			crit = append(crit, data)
		case "High":
			high = append(high, data)
		case "Medium":
			med = append(med, data)
		case "Low":
			low = append(low, data)
		}
	}

	// Sort each severity tier by score separately
	sort.SliceStable(crit, func(i, j int) bool {
		return crit[i].Score > crit[j].Score
	})
	sort.SliceStable(high, func(i, j int) bool {
		return high[i].Score > high[j].Score
	})
	sort.SliceStable(med, func(i, j int) bool {
		return med[i].Score > med[j].Score
	})
	sort.SliceStable(low, func(i, j int) bool {
		return low[i].Score > low[j].Score
	})

	// Combine now to one mega slice
	var data []ImageVulnerabilityData
	data = append(data, crit...)
	data = append(data, high...)
	data = append(data, med...)
	data = append(data, low...)
	v.Data = data
	return v
}
