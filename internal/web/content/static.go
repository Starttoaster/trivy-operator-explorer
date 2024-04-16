package content

import "embed"

// Static contains an embedded filesystem
var Static embed.FS

// Init accepts an embedded filesystem for the web package content
func Init(fs embed.FS) {
	Static = fs
}
