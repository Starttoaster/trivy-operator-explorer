package main

import (
	"embed"

	"github.com/starttoaster/trivy-operator-explorer/cmd"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
)

//go:generate tailwindcss build -i ./static/css/input.css -o ./static/css/output.css

//go:embed static/sidebar.html
//go:embed static/configaudits.html
//go:embed static/configaudit.html
//go:embed static/clusteraudits.html
//go:embed static/clusteraudit.html
//go:embed static/roles.html
//go:embed static/role.html
//go:embed static/clusterroles.html
//go:embed static/clusterrole.html
//go:embed static/images.html
//go:embed static/image.html
//go:embed static/css/output.css
//go:embed static/css/extra.css
var static embed.FS

func main() {
	content.Init(static)
	cmd.Execute()
}
