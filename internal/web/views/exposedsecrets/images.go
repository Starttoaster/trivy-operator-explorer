package images

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// GetView converts some report data to the /exposedsecrets view
func GetView(data *v1alpha1.ExposedSecretReportList) View {
	var i View

	for _, item := range data.Items {
		image := Data{
			Name:   getImageNameFromLabels(item.Report.Registry.Server, item.Report.Artifact.Repository, item.Report.Artifact.Tag),
			Digest: item.Report.Artifact.Digest,
		}
		resourceData := ResourceMetadata{
			Kind:      item.ObjectMeta.Labels["trivy-operator.resource.kind"],
			Name:      item.ObjectMeta.Labels["trivy-operator.resource.name"],
			Namespace: item.ObjectMeta.Labels["trivy-operator.resource.namespace"],
		}
		image.Resources = make(map[ResourceMetadata]struct{})
		image.Resources[resourceData] = struct{}{}

		// Check if the image used is unique, by fullname (registry/repository:tag) and digest
		// This check is a little inefficient because it loops through the whole image list
		// I was previously using maps for uniqueness and then converted over to slices because they're easier to sort server-side
		imageIndex, uniqueImage := i.isUniqueImage(image.Name, image.Digest)

		// Add image if unique, retrieving the new image's data index in the slice
		if uniqueImage {
			i = append(i, image)
			imageIndex = len(i) - 1
		} else {
			// Add this resource to the image at the given index if image data already present
			i[imageIndex].Resources[resourceData] = struct{}{}
		}

		for _, v := range item.Report.Secrets {
			// Construct this secret's view data
			secret := Secret{
				Severity: string(v.Severity),
				Title:    v.Title,
				Target:   v.Target,
				Match:    v.Match,
			}

			uniqueSecret := i[imageIndex].isUniqueImageSecret(secret.Severity, secret.Title, secret.Target, secret.Match)
			if uniqueSecret {
				i[imageIndex].addSecretData(secret)
			}
		}
	}

	i = sortView(i)

	return i
}

func sortView(i View) View {
	// Sort the slice by severity in descending order
	sort.Slice(i, func(j, k int) bool {
		if len(i[j].Critical) != len(i[k].Critical) {
			return len(i[j].Critical) > len(i[k].Critical)
		}

		if len(i[j].High) != len(i[k].High) {
			return len(i[j].High) > len(i[k].High)
		}

		if len(i[j].Medium) != len(i[k].Medium) {
			return len(i[j].Medium) > len(i[k].Medium)
		}

		return len(i[j].Low) > len(i[k].Low)
	})

	return i
}

func (i View) isUniqueImage(name, digest string) (int, bool) {
	for index, image := range i {
		if name == image.Name && digest == image.Digest {
			return index, false
		}
	}

	return 0, true
}

func (i Data) isUniqueImageSecret(severity, title, target, match string) bool {
	switch strings.ToLower(severity) {
	case "critical":
		for _, secret := range i.Critical {
			if title == secret.Title && target == secret.Target && match == secret.Match {
				return false
			}
		}
	case "high":
		for _, secret := range i.High {
			if title == secret.Title && target == secret.Target && match == secret.Match {
				return false
			}
		}
	case "medium":
		for _, secret := range i.Medium {
			if title == secret.Title && target == secret.Target && match == secret.Match {
				return false
			}
		}
	case "low":
		for _, secret := range i.Low {
			if title == secret.Title && target == secret.Target && match == secret.Match {
				return false
			}
		}
	}

	return true
}

func (i *Data) addSecretData(v Secret) {
	switch strings.ToLower(v.Severity) {
	case "critical":
		i.Critical = append(i.Critical, v)
	case "high":
		i.High = append(i.High, v)
	case "medium":
		i.Medium = append(i.Medium, v)
	case "low":
		i.Low = append(i.Low, v)
	}

}

func getImageNameFromLabels(registry, repo, tag string) string {
	if registry == "index.docker.io" {
		// If Docker Hub, trim the registry prefix for readability
		// Also trims `library/` from the prefix of the image name, which is a hidden username for Docker Hub official images
		return fmt.Sprintf("%s:%s", strings.TrimPrefix(repo, "library/"), tag)
	}
	return fmt.Sprintf("%s/%s:%s", registry, repo, tag)
}
