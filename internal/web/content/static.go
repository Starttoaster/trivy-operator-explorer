package content

import "embed"

var Static embed.FS

func Init(fs embed.FS) {
	Static = fs
}
