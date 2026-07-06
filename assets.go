// Package assets embeds the frontend's static web content (HTML templates, CSS,
// JS, and icons). It lives at the repository root because go:embed can only
// reference files at or below the embedding source file's directory, and the
// static/ tree sits at the repo root.
package assets

import "embed"

//go:generate tailwindcss -i ./static/css/input.css -o ./static/css/output.css

//go:embed static
var Static embed.FS
