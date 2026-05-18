package images

// View a list of data about images and their secrets
type View []Data

// Data contains data about an image and its exposed secrets
type Data struct {
	Name      string                        `json:"name"`   // name of the image
	Digest    string                        `json:"digest"` // sha digest of the image
	Resources map[ResourceMetadata]struct{} `json:"-"`      // data about resources using this image (serialized via custom MarshalJSON)
	Critical  []Secret                      `json:"critical"`
	High      []Secret                      `json:"high"`
	Medium    []Secret                      `json:"medium"`
	Low       []Secret                      `json:"low"`
}

// ResourceMetadata data related to a k8s resource using an image
type ResourceMetadata struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Secret data related to an exposed secret
type Secret struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Target   string `json:"target"`
	Match    string `json:"match"`
}
