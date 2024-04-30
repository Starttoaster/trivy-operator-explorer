package image

// View data about an image and their exposed secrets
type View Data

// Data contains data about an image and its exposed secrets
type Data struct {
	Name    string // name of the image
	Digest  string // sha digest of the image
	Secrets []Secret
}

// Secret data related to an exposed secret
type Secret struct {
	Severity string
	Title    string
	Target   string
	Match    string
}
