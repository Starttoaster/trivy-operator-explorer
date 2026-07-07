// Command frontend serves the trivy-operator-explorer web UI, JSON API, and MCP
// server. It reads report bundles that collectors have written to an S3 bucket
// (one prefix per cluster) and keeps a refreshing in-memory cache of them. The
// only local state it owns is the sqlite "ignored CVE" database.
package main

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	assets "github.com/starttoaster/trivy-operator-explorer"
	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/mcp"
	"github.com/starttoaster/trivy-operator-explorer/internal/source"
	"github.com/starttoaster/trivy-operator-explorer/internal/store"
	"github.com/starttoaster/trivy-operator-explorer/internal/web"
	"github.com/starttoaster/trivy-operator-explorer/internal/web/content"
)

var rootCmd = &cobra.Command{
	Use:   "trivy-operator-explorer",
	Short: "A web frontend for trivy-operator scan reports collected into S3",

	Run: func(_ *cobra.Command, _ []string) {
		content.Init(assets.Static)

		if err := db.Init(viper.GetString("db-path")); err != nil {
			log.Fatal("Error initializing DB", "error", err)
		}

		if viper.GetString("log-level") == "" {
			log.Fatal("Log level flag not set. Should be info by default. This likely means it was overridden by user input with no value.")
		}
		log.Init(viper.GetString("log-level"))

		bucket := viper.GetString("s3-bucket")
		if bucket == "" {
			log.Fatal("s3-bucket flag is required")
		}

		st, err := store.New(context.Background(), bucket, viper.GetString("s3-prefix"), viper.GetString("s3-region"))
		if err != nil {
			log.Fatal("error initializing S3 store", "error", err)
		}

		if err := source.Init(st, viper.GetDuration("cache-refresh-interval")); err != nil {
			log.Fatal("error initializing report source", "error", err)
		}

		if viper.GetString("server-port") == "" {
			log.Fatal("server port flag not set. Should be 8080 by default. This likely means it was overridden by user input with no value.")
		}
		if viper.GetString("mcp-port") == "" {
			log.Fatal("mcp port flag not set. Should be 8081 by default. This likely means it was overridden by user input with no value.")
		}

		// Start the web server and the MCP server concurrently. They share the
		// same S3-backed report cache and sqlite connection but listen on
		// independent ports so the MCP surface can be exposed (or firewalled)
		// separately from the UI/JSON API. The first server to return takes the
		// process down.
		errCh := make(chan error, 2)
		go func() { errCh <- web.Start(viper.GetString("server-port")) }()
		go func() { errCh <- mcp.Start(viper.GetString("mcp-port")) }()
		cobra.CheckErr(<-errCh)
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	viper.SetEnvPrefix("TRIVY_OPERATOR_EXPLORER")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().String("log-level", "info", "The log-level for the application, can be one of info, warn, error, debug.")
	rootCmd.PersistentFlags().Uint16("server-port", 8080, "The port the web/API server binds to.")
	rootCmd.PersistentFlags().Uint16("mcp-port", 8081, "The port the Model Context Protocol (MCP) server binds to. Served at the /mcp path over Streamable HTTP.")
	rootCmd.PersistentFlags().String("db-path", "./", "The path to the directory containing the sqlite database.")
	rootCmd.PersistentFlags().String("s3-bucket", "", "The S3 bucket to read cluster report bundles from.")
	rootCmd.PersistentFlags().String("s3-prefix", "", "The key prefix within the S3 bucket under which cluster report bundles live.")
	rootCmd.PersistentFlags().String("s3-region", "", "The AWS region of the S3 bucket. If empty, the AWS SDK default resolution is used.")
	rootCmd.PersistentFlags().Duration("cache-refresh-interval", 5*time.Minute, "How often to reload cluster report bundles from S3.")

	bindings := []string{
		"log-level", "server-port", "mcp-port", "db-path",
		"s3-bucket", "s3-prefix", "s3-region", "cache-refresh-interval",
	}
	for _, name := range bindings {
		if err := viper.BindPFlag(name, rootCmd.PersistentFlags().Lookup(name)); err != nil {
			log.Init("info")
			log.Fatal("Error binding flag to key", "flag", name, "error", err)
		}
	}

	log.Init(viper.GetString("log-level"))
}
