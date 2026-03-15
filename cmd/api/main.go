package main

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/starttoaster/trivy-operator-explorer/internal/api"
	"github.com/starttoaster/trivy-operator-explorer/internal/db"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "trivy-explorer-api",
		Short: "Central API that receives data from agents and stores in Postgres",
		Run: func(cmd *cobra.Command, args []string) {
			log.Init(viper.GetString("log-level"))

			dsn := viper.GetString("db-dsn")
			if dsn == "" {
				log.Fatal("db-dsn is required")
			}

			if err := db.Init(dsn); err != nil {
				log.Fatal("error initializing database", "error", err.Error())
			}

			cfg := api.ServerConfig{
				ListenAddr: viper.GetString("listen-addr"),
				CertFile:   viper.GetString("tls-cert-file"),
				KeyFile:    viper.GetString("tls-key-file"),
				CAFile:     viper.GetString("tls-ca-file"),
			}

			if err := api.Start(cfg); err != nil {
				log.Fatal("API server error", "error", err.Error())
			}
		},
	}

	viper.SetEnvPrefix("TRIVY_API")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	rootCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().String("db-dsn", "", "Postgres connection string")
	rootCmd.Flags().String("listen-addr", ":8443", "Address to listen on")
	rootCmd.Flags().String("tls-cert-file", "", "Path to TLS server certificate")
	rootCmd.Flags().String("tls-key-file", "", "Path to TLS server key")
	rootCmd.Flags().String("tls-ca-file", "", "Path to CA certificate for verifying client certs")

	for _, f := range []string{"log-level", "db-dsn", "listen-addr", "tls-cert-file", "tls-key-file", "tls-ca-file"} {
		err := viper.BindPFlag(f, rootCmd.Flags().Lookup(f))
		if err != nil {
			log.Init("info") // call this first to init possibly nil logger
			log.Fatal("failed to bind flag", "error", err.Error())
		}
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
