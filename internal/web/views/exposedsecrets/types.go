package images

// View a list of data about images and their secrets
type View []Data

// Data contains data about an image and its exposed secrets
type Data struct {
	Name      string                        // name of the image
	Digest    string                        // sha digest of the image
	Resources map[ResourceMetadata]struct{} // data about resources using this image
	Critical  []Secret
	High      []Secret
	Medium    []Secret
	Low       []Secret
}

// ResourceMetadata data related to a k8s resource using an image
type ResourceMetadata struct {
	Kind      string
	Name      string
	Namespace string
}

// Secret data related to an exposed secret
type Secret struct {
	Severity string
	Title    string
	Target   string
	Match    string
}
