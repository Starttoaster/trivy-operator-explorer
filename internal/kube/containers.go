package kube

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerImage contains the metadata for a container image
type ContainerImage struct {
	Name      string
	Tag       string
	Digest    string
	Resources map[ResourceMetadata]struct{} // data about resources using this image
}

// ResourceMetadata data related to a k8s Pod
type ResourceMetadata struct {
	Kind      string
	Name      string
	Namespace string
}

// GetContainerImagesMap retrieves all container image metadata about running images
func GetContainerImagesMap() (map[string]ContainerImage, error) {
	var list corev1.PodList
	err := coreClient.Get().
		Resource("pods").
		VersionedParams(&metav1.ListOptions{}, metav1.ParameterCodec).
		Do(context.Background()).
		Into(&list)
	if err != nil {
		return nil, err
	}

	imageMap := make(map[string]ContainerImage)

	for _, pod := range list.Items {
		// Checks init and regular containers
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...)

		// Process each container
		for _, container := range allContainers {
			imageName, imageTag, err := parseImageReference(container.Image)
			if err != nil {
				return nil, err
			}
			if imageName == "" || imageTag == "" {
				continue
			}

			// Create unique key from name, tag, and digest
			key := fmt.Sprintf("%s:%s", imageName, imageTag)

			// Check if image is already in map
			meta := getImageResourceMetadata(pod)
			if _, ok := imageMap[key]; !ok {
				imageMap[key] = ContainerImage{
					Name:      imageName,
					Tag:       imageTag,
					Resources: meta,
				}
			} else {
				existingResourceMap := imageMap[key].Resources
				newResourceMap := make(map[ResourceMetadata]struct{}, 1)
				for k, v := range existingResourceMap {
					newResourceMap[k] = v
				}
				for k, v := range meta {
					newResourceMap[k] = v
				}

				imageMap[key] = ContainerImage{
					Name:      imageName,
					Tag:       imageTag,
					Resources: newResourceMap,
				}
			}
		}
	}
	return imageMap, nil
}

func getImageResourceMetadata(pod corev1.Pod) map[ResourceMetadata]struct{} {
	resList := make(map[ResourceMetadata]struct{}, 1)

	// If no owner references, just return this Pod
	if len(pod.OwnerReferences) == 0 {
		resList[ResourceMetadata{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace}] = struct{}{}
		return resList
	}

	// If owner references found, put each in the resource meta list
	for _, owner := range pod.OwnerReferences {
		resList[ResourceMetadata{
			Kind:      owner.Kind,
			Name:      owner.Name,
			Namespace: pod.Namespace,
		}] = struct{}{}
	}
	return resList
}

// GetContainerImages retrieves all container image metadata about running images
func GetContainerImages() ([]ContainerImage, error) {
	imageMap, err := GetContainerImagesMap()
	if err != nil {
		return nil, err
	}

	// Convert map to slice
	images := make([]ContainerImage, 0, len(imageMap))
	for _, img := range imageMap {
		images = append(images, img)
	}

	return images, nil
}

// ParseImageRef splits a docker-ish image reference into:
//   - repo: "$registry/$name" (or just "$name" if no registry was included)
//   - suffix:
//   - "tag" for "$repo:$tag" and "$repo:$tag@sha256:..."
//   - "sha256:..." for "$repo@sha256:..."
//   - "" if neither tag nor digest is present
//
// Images can come in the following formats
//   - $registry/$name:$tag
//   - $registry/$name:$tag@sha256:$hash
//   - $registry/$name@sha256:$hash
func parseImageReference(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty image reference")
	}

	// Split off digest if present: "...@sha256:..."
	var beforeDigest, digest string
	if at := strings.IndexByte(s, '@'); at >= 0 {
		beforeDigest = s[:at]
		digest = s[at+1:] // everything after '@'
	} else {
		beforeDigest = s
	}

	var repo string

	// Find a tag separator in beforeDigest. We must ignore ':' that are part of
	// a registry host:port, so we only treat ':' occurring AFTER the last '/' as a tag.
	lastSlash := strings.LastIndexByte(beforeDigest, '/')
	tagSep := strings.LastIndexByte(beforeDigest, ':')
	hasTag := tagSep > lastSlash

	if hasTag {
		repo = beforeDigest[:tagSep]
		tag := beforeDigest[tagSep+1:]
		if tag == "" {
			return "", "", fmt.Errorf("invalid image reference: empty tag")
		}
		// If it was "$repo:$tag@sha256:..." we only want the tag
		return strings.TrimPrefix(repo, "docker.io/"), tag, nil
	}

	// No tag in beforeDigest, so repo is the whole thing before '@' (or entire string)
	repo = beforeDigest

	// If it was "$repo@sha256:..." we want everything after '@'
	if digest != "" {
		return strings.TrimPrefix(repo, "docker.io/"), digest, nil
	}

	// No tag, no digest.
	return "", "", nil
}
