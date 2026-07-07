// Command collector runs inside a Kubernetes cluster, reads the trivy-operator
// custom resources (plus running-pod/container data), and writes a copy of them
// into an S3 bucket namespaced by cluster name. The bucket can be shared by
// many clusters (multi-tenant); the frontend reads all of them.
package main

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/starttoaster/trivy-operator-explorer/internal/collect"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/store"
)

var rootCmd = &cobra.Command{
	Use:   "trivy-operator-collector",
	Short: "Copies trivy-operator scan reports from a cluster into an S3 bucket",

	Run: func(_ *cobra.Command, _ []string) {
		if viper.GetString("log-level") == "" {
			log.Fatal("Log level flag not set. Should be info by default. This likely means it was overridden by user input with no value.")
		}
		log.Init(viper.GetString("log-level"))

		clusterName := viper.GetString("cluster-name")
		if clusterName == "" {
			log.Fatal("cluster-name flag is required")
		}

		bucket := viper.GetString("s3-bucket")
		if bucket == "" {
			log.Fatal("s3-bucket flag is required")
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

		st, err := store.New(context.Background(), bucket, viper.GetString("s3-prefix"), viper.GetString("s3-region"))
		if err != nil {
			log.Fatal("error initializing S3 store", "error", err)
		}

		log.Logger.Info("collector starting",
			"cluster", clusterName,
			"bucket", bucket,
			"prefix", viper.GetString("s3-prefix"),
			"interval", viper.GetDuration("sync-interval").String(),
		)

		collect.Run(context.Background(), st, clusterName, viper.GetDuration("sync-interval"))
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	viper.SetEnvPrefix("TRIVY_OPERATOR_COLLECTOR")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().String("log-level", "info", "The log-level for the application, can be one of info, warn, error, debug.")
	rootCmd.PersistentFlags().String("cluster-name", "", "The name of this cluster, used as the S3 key namespace for its reports.")
	rootCmd.PersistentFlags().String("kubeconfig", "", "The path to a kubeconfig. Assumes in-cluster configuration if left blank.")
	rootCmd.PersistentFlags().String("s3-bucket", "", "The S3 bucket to write cluster report bundles to.")
	rootCmd.PersistentFlags().String("s3-prefix", "", "The key prefix within the S3 bucket under which this cluster's reports are written.")
	rootCmd.PersistentFlags().String("s3-region", "", "The AWS region of the S3 bucket. If empty, the AWS SDK default resolution is used.")
	rootCmd.PersistentFlags().Duration("sync-interval", 5*time.Minute, "How often to read the cluster's reports and write them to S3.")

	bindings := []string{
		"log-level", "cluster-name", "kubeconfig",
		"s3-bucket", "s3-prefix", "s3-region", "sync-interval",
	}
	for _, name := range bindings {
		if err := viper.BindPFlag(name, rootCmd.PersistentFlags().Lookup(name)); err != nil {
			log.Init("info")
			log.Fatal("Error binding flag to key", "flag", name, "error", err)
		}
	}

	log.Init(viper.GetString("log-level"))
}
