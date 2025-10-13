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
			imageName, imageTag := parseImageReference(container.Image)

			// Create unique key from name, tag, and digest
			key := fmt.Sprintf("%s:%s", imageName, imageTag)

			// Check if image is already in map
			if _, ok := imageMap[key]; !ok {
				resMap := make(map[ResourceMetadata]struct{})
				for _, res := range getImageResourceMetadata(pod) {
					resMap[res] = struct{}{}
				}
				imageMap[key] = ContainerImage{
					Name:      imageName,
					Tag:       imageTag,
					Resources: resMap,
				}
			} else {
				for _, res := range getImageResourceMetadata(pod) {
					imageMap[key].Resources[res] = struct{}{}
				}
			}
		}
	}

	return imageMap, nil
}

func getImageResourceMetadata(pod corev1.Pod) []ResourceMetadata {
	resList := make([]ResourceMetadata, 0)

	// If no owner references, just return this Pod
	if len(pod.OwnerReferences) == 0 {
		resList = append(resList, ResourceMetadata{
			Kind:      "Pod",
			Name:      pod.Name,
			Namespace: pod.Namespace,
		})
		return resList
	}

	// If owner references found, put each in the resource meta list
	for _, owner := range pod.OwnerReferences {
		resList = append(resList, ResourceMetadata{
			Kind:      owner.Kind,
			Name:      owner.Name,
			Namespace: pod.Namespace,
		})
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

// parseImageReference splits an image reference into name and tag
func parseImageReference(image string) (string, string) {
	// Image strings can come in two varieties:
	// $registry/$name:$tag or $registry/$name:$tag@sha256:$hash

	splitWithDigest := strings.Split(image, "@")
	splitWithTag := strings.Split(splitWithDigest[0], ":")
	return strings.TrimPrefix(splitWithTag[0], "docker.io/"), splitWithTag[1]
}
