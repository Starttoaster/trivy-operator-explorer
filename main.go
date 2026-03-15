package main

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/web"
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
//go:embed static/compliancereports.html
//go:embed static/compliancereport.html
//go:embed static/index.html
//go:embed static/img/t.ico
//go:embed static/css/output.css
//go:embed static/css/extra.css
//go:embed static/js/chart.js
//go:embed static/js/images-hasfix.js
//go:embed static/js/images-resources-table.js
//go:embed static/js/image-resources.js
//go:embed static/js/image-ignore.js
var static embed.FS

func main() {
	content.Init(static)

	rootCmd := &cobra.Command{
		Use:   "trivy-operator-explorer",
		Short: "Web frontend for exploring trivy-operator data across clusters",
		Run: func(cmd *cobra.Command, args []string) {
			log.Init(viper.GetString("log-level"))

			dsn := viper.GetString("db-dsn")
			if dsn == "" {
				log.Fatal("db-dsn is required")
			}

			if err := db.Init(dsn); err != nil {
				log.Fatal("error initializing database", "error", err.Error())
			}

			port := viper.GetString("server-port")
			if port == "" {
				log.Fatal("server-port is required")
			}

			if err := web.Start(port); err != nil {
				log.Fatal("web server error", "error", err.Error())
			}
		},
	}

	viper.SetEnvPrefix("TRIVY_OPERATOR_EXPLORER")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	rootCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().Uint16("server-port", 8080, "Port the web server binds to")
	rootCmd.Flags().String("db-dsn", "", "Postgres connection string")

	for _, f := range []string{"log-level", "server-port", "db-dsn"} {
		if err := viper.BindPFlag(f, rootCmd.Flags().Lookup(f)); err != nil {
			fmt.Printf("error binding flag %s: %v\n", f, err)
			os.Exit(1)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
