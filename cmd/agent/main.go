package main

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/starttoaster/trivy-operator-explorer/internal/agent"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
)

const defaultSyncInterval = 5 * time.Minute

func main() {
	rootCmd := &cobra.Command{
		Use:   "trivy-explorer-agent",
		Short: "Agent that watches trivy-operator CRDs and syncs to the central API",
		Run: func(cmd *cobra.Command, args []string) {
			log.Init(viper.GetString("log-level"))

			clusterName := viper.GetString("cluster-name")
			if clusterName == "" {
				log.Fatal("cluster-name is required. This value should be unique for each cluster the trivy explorer agent is installed in.")
			}

			apiURL := viper.GetString("api-url")
			if apiURL == "" {
				log.Fatal("api-url is required")
			}

			syncInterval := viper.GetDuration("sync-interval")
			if syncInterval == 0 {
				syncInterval = defaultSyncInterval
			}

			kubeconfig := viper.GetString("kubeconfig")
			if kubeconfig == "" {
				if err := kube.InitClient(true, ""); err != nil {
					log.Fatal("error initing in-cluster kube client", "error", err.Error())
				}
			} else {
				if err := kube.InitClient(false, kubeconfig); err != nil {
					log.Fatal("error initing external kube client", "error", err.Error())
				}
			}

			client, err := agent.NewClient(agent.ClientConfig{
				APIURL:   apiURL,
				CertFile: viper.GetString("tls-cert-file"),
				KeyFile:  viper.GetString("tls-key-file"),
				CAFile:   viper.GetString("tls-ca-file"),
			})
			if err != nil {
				log.Fatal("error creating API client", "error", err.Error())
			}

			w := agent.NewWatcher(agent.WatcherConfig{
				ClusterName:  clusterName,
				SyncInterval: syncInterval,
				Client:       client,
			})
			w.Run()
		},
	}

	viper.SetEnvPrefix("TRIVY_AGENT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	rootCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().String("cluster-name", "", "Name identifying this cluster")
	rootCmd.Flags().String("api-url", "", "URL of the central API (e.g. https://api.example.com:8443)")
	rootCmd.Flags().Duration("sync-interval", defaultSyncInterval, "Interval between syncs")
	rootCmd.Flags().String("tls-cert-file", "", "Path to mTLS client certificate")
	rootCmd.Flags().String("tls-key-file", "", "Path to mTLS client key")
	rootCmd.Flags().String("tls-ca-file", "", "Path to CA certificate for verifying the API server")
	rootCmd.Flags().String("kubeconfig", "", "Path to kubeconfig (defaults to in-cluster)")

	for _, f := range []string{"log-level", "cluster-name", "api-url", "sync-interval", "tls-cert-file", "tls-key-file", "tls-ca-file", "kubeconfig"} {
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
