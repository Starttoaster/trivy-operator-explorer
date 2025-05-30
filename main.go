package main

import (
	"embed"

	"github.com/starttoaster/trivy-operator-explorer/cmd"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
)

//go:generate tailwindcss -i ./static/css/input.css -o ./static/css/output.css

//go:embed static/sidebar.html
//go:embed static/configaudits.html
//go:embed static/configaudit.html
//go:embed static/clusteraudits.html
//go:embed static/clusteraudit.html
//go:embed static/roles.html
//go:embed static/role.html
//go:embed static/clusterroles.html
//go:embed static/clusterrole.html
//go:embed static/exposedsecrets.html
//go:embed static/exposedsecret.html
//go:embed static/images.html
//go:embed static/image.html
//go:embed static/index.html
//go:embed static/img/t.ico
//go:embed static/css/output.css
//go:embed static/css/extra.css
//go:embed static/js/chart.js
//go:embed static/js/images-hasfix.js
//go:embed static/js/images-resources-table.js
//go:embed static/js/image-resources.js
var static embed.FS

func main() {
	content.Init(static)
	cmd.Execute()
}
