package images

import (
	"encoding/json"
	"sort"
	"strings"
)

// ClusterList returns the cluster names running this image as a stable,
// comma-separated string for display in the aggregate images table.
func (d Data) ClusterList() string {
	return strings.Join(d.sortedClusters(), ", ")
}

// sortedClusters returns the cluster names as a stable sorted slice.
func (d Data) sortedClusters() []string {
	clusters := make([]string, 0, len(d.Clusters))
	for c := range d.Clusters {
		if c == "" {
			continue
		}
		clusters = append(clusters, c)
	}
	sort.Strings(clusters)
	return clusters
}

// MarshalJSON implements json.Marshaler for Data so that the Resources
// set-map (which uses a struct key unsupported by encoding/json) is emitted
// as a stable, sorted JSON array of resource objects.
func (d Data) MarshalJSON() ([]byte, error) {
	type alias Data
	resources := make([]ResourceMetadata, 0, len(d.Resources))
	for r := range d.Resources {
		resources = append(resources, r)
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Namespace != resources[j].Namespace {
			return resources[i].Namespace < resources[j].Namespace
		}
		if resources[i].Kind != resources[j].Kind {
			return resources[i].Kind < resources[j].Kind
		}
		return resources[i].Name < resources[j].Name
	})
	return json.Marshal(struct {
		alias
		Clusters  []string           `json:"clusters"`
		Resources []ResourceMetadata `json:"resources"`
	}{alias(d), d.sortedClusters(), resources})
}
