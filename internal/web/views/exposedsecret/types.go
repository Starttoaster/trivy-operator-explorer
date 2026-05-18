package image

// View data about an image and their exposed secrets
type View Data

// Data contains data about an image and its exposed secrets
type Data struct {
	Name    string   `json:"name"`   // name of the image
	Digest  string   `json:"digest"` // sha digest of the image
	Secrets []Secret `json:"secrets"`
}

// Secret data related to an exposed secret
type Secret struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Target   string `json:"target"`
	Match    string `json:"match"`
}
