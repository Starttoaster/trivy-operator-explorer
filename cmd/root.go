package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/starttoaster/trivy-operator-explorer/internal/kube"
	log "github.com/starttoaster/trivy-operator-explorer/internal/logger"
	"github.com/starttoaster/trivy-operator-explorer/internal/web"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "trivy-operator-explorer",
	Short: "An explorer for metrics exported from AquaSecurity's Trivy operator",

	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("log-level") == "" {
			// Logger is nil still so need to use fmt
			fmt.Println("Log level flag not set. Should be info by default. This likely means it was overridden by user input with no value.")
			os.Exit(1)
		}
		log.Init(viper.GetString("log-level"))

		kubeconfig := viper.GetString("kubeconfig")
		if kubeconfig == "" {
			err := kube.InitClient(true, "")
			if err != nil {
				log.Logger.Error("error initing in-cluster kube client", "error", err.Error())
				os.Exit(1)
			}
		} else {
			err := kube.InitClient(false, kubeconfig)
			if err != nil {
				log.Logger.Error("error initing external kube client", "error", err.Error())
				os.Exit(1)
			}
		}

		if viper.GetString("server-port") == "" {
			log.Logger.Error("server port flag not set. Should be 8080 by default. This likely means it was overridden by user input with no value.")
			os.Exit(1)
		}
		cobra.CheckErr(web.Start(viper.GetString("server-port")))
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	// Read in environment variables that match defined config pattern
	viper.SetEnvPrefix("TRIVY_OPERATOR_EXPLORER")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().String("log-level", "info", "The log-level for the application, can be one of info, warn, error, debug.")
	rootCmd.PersistentFlags().Uint16("server-port", 8080, "The port the metrics server binds to.")
	rootCmd.PersistentFlags().String("kubeconfig", "", "The path to a kubeconfig. Assumes in-cluster configuration if left blank.")

	err := viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	if err != nil {
		log.Logger.Error(err.Error())
		os.Exit(1)
	}

	err = viper.BindPFlag("server-port", rootCmd.PersistentFlags().Lookup("server-port"))
	if err != nil {
		log.Logger.Error(err.Error())
		os.Exit(1)
	}

	err = viper.BindPFlag("kubeconfig", rootCmd.PersistentFlags().Lookup("kubeconfig"))
	if err != nil {
		log.Logger.Error(err.Error())
		os.Exit(1)
	}
}
