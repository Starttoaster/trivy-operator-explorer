package images

import (
	"encoding/json"
	"sort"
)

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
		Resources []ResourceMetadata `json:"resources"`
	}{alias(d), resources})
}
