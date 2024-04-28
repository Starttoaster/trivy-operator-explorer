package views

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

/*
	apiVersion: aquasecurity.github.io/v1alpha1
	kind: VulnerabilityReport
	metadata:
	  labels:
	    resource-spec-hash: 6cfb9465db
	    trivy-operator.container.name: kube-router
	    trivy-operator.resource.kind: DaemonSet
	    trivy-operator.resource.name: kube-router
	    trivy-operator.resource.namespace: kube-system
	  name: daemonset-kube-router-kube-router
	  namespace: kube-system
	report:
	  artifact:
	    digest: sha256:e21abd397695e37937d411acf71a94cb36c18194d14c81775b43c896dc99639b
	    repository: k0sproject/kube-router
	    tag: v1.6.0-iptables1.8.9-1
	  os:
	    family: alpine
	    name: 3.18.5
	  registry:
	    server: quay.io
	  scanner:
	    name: Trivy
	    vendor: Aqua Security
	    version: 0.50.1
	  summary:
	    criticalCount: 0
	    highCount: 0
	    lowCount: 2
	    mediumCount: 13
	    noneCount: 0
	    unknownCount: 0
	  updateTimestamp: '2024-04-28T02:15:57Z'
	  vulnerabilities:
	    - fixedVersion: 3.1.4-r3
	      installedVersion: 3.1.4-r1
	      lastModifiedDate: '2024-04-26T09:15:08Z'
	      links: []
	      primaryLink: https://avd.aquasec.com/nvd/cve-2023-6129
	      publishedDate: '2024-01-09T17:15:12Z'
	      resource: libcrypto3
	      score: 6.5
	      severity: MEDIUM
	      target: ''
	      title: >-
	        mysql: openssl: POLY1305 MAC implementation corrupts vector registers on
	        PowerPC
	      vulnerabilityID: CVE-2023-6129
	    - fixedVersion: 3.1.4-r4
	      installedVersion: 3.1.4-r1
	      lastModifiedDate: '2024-04-25T13:18:13Z'
	      links: []
	      primaryLink: https://avd.aquasec.com/nvd/cve-2023-6237
	      publishedDate: '2024-04-25T07:15:45Z'
	      resource: libcrypto3
	      score: 5.9
	      severity: MEDIUM
	      target: ''
	      title: 'openssl: Excessive time spent checking invalid RSA public keys'
	      vulnerabilityID: CVE-2023-6237
	    - fixedVersion: 3.1.4-r5
	      installedVersion: 3.1.4-r1
	      lastModifiedDate: '2024-02-08T10:15:13Z'
	      links: []
	      primaryLink: https://avd.aquasec.com/nvd/cve-2024-0727
	      publishedDate: '2024-01-26T09:15:07Z'
	      resource: libcrypto3
	      score: 5.5
	      severity: MEDIUM
	      target: ''
	      title: 'openssl: denial of service via null dereference'
	      vulnerabilityID: CVE-2024-0727
*/

// GetImagesView converts some scrape data to the /images view
func GetImagesView(data *v1alpha1.VulnerabilityReportList) ImagesView {
	var i ImagesView
	i.Images = make(map[Image]ImageData)

	for _, item := range data.Items {
		image := Image{
			Name:   getImageNameFromLabels(item.Report.Registry.Server, item.Report.Artifact.Repository, item.Report.Artifact.Tag),
			Digest: item.Report.Artifact.Digest,
		}
		resourceData := ResourceMetadata{
			Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
			Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
		}

		for _, v := range item.Report.Vulnerabilities {
			score := float32(0.0)
			if v.Score != nil {
				score = float32(*v.Score)
			}
			cveID := v.VulnerabilityID
			vuln := Vulnerability{
				Severity:          string(v.Severity),
				Score:             score,
				URL:               v.PrimaryLink,
				Resource:          v.Resource,
				Title:             v.Title,
				VulnerableVersion: v.InstalledVersion,
				FixedVersion:      v.FixedVersion,
			}

			// Check if this image is already in the map
			_, ok := i.Images[image]
			if ok {
				// Add to the image's vulnerability list if it hasn't been yet
				_, ok := i.Images[image].Vulnerabilities[cveID]
				if !ok {
					i.Images[image].Vulnerabilities[cveID] = vuln
				}

				// Add to the list of Resources using this image if it hasn't been yet
				_, ok = i.Images[image].Resources[resourceData]
				if !ok {
					i.Images[image].Resources[resourceData] = struct{}{}
				}
			} else {
				resMap := make(map[ResourceMetadata]struct{})
				vulnMap := make(map[string]Vulnerability)
				imageData := ImageData{
					Name:                    image.Name,
					Digest:                  image.Digest,
					Vulnerabilities:         vulnMap,
					Resources:               resMap,
					CriticalVulnerabilities: item.Report.Summary.CriticalCount,
					HighVulnerabilities:     item.Report.Summary.HighCount,
					MediumVulnerabilities:   item.Report.Summary.MediumCount,
					LowVulnerabilities:      item.Report.Summary.LowCount,
					OSFamily:                string(item.Report.OS.Family),
					OSVersion:               item.Report.OS.Name,
				}
				if item.Report.OS.Eosl {
					imageData.OSEndOfServiceLife = "true"
				}
				imageData.Vulnerabilities[cveID] = vuln
				imageData.Resources[resourceData] = struct{}{}
				i.Images[image] = imageData
			}
		}
	}

	i = sortImagesView(i)

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

func getImageNameFromLabels(registry, repo, tag string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, trim the registry prefix for readability
		// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(repo, "library/"), tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}
