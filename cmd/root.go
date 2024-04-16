package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

		if viper.GetString("server-port") == "" {
			log.Logger.Error("server port flag not set. Should be 8080 by default. This likely means it was overridden by user input with no value.")
			os.Exit(1)
		}
		if viper.GetString("metrics-endpoint") == "" {
			log.Logger.Error("metrics endpoint flag not set. Set with the --metrics-endpoint flag or TRIVY_OPERATOR_EXPLORER_METRICS_ENDPOINT environment variable.")
			os.Exit(1)
		}
		cobra.CheckErr(web.Start(viper.GetString("server-port"), viper.GetString("metrics-endpoint")))
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
	rootCmd.PersistentFlags().String("metrics-endpoint", "", "The URL to your Trivy Operator metrics endpoint (eg. http://trivy-operator.trivy-system.svc.cluster.local/metrics)")
	rootCmd.PersistentFlags().Uint16("server-port", 8080, "The port the metrics server binds to.")

	err := viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	if err != nil {
		log.Logger.Error(err.Error())
		os.Exit(1)
	}

	err = viper.BindPFlag("metrics-endpoint", rootCmd.PersistentFlags().Lookup("metrics-endpoint"))
	if err != nil {
		log.Logger.Error(err.Error())
		os.Exit(1)
	}

	err = viper.BindPFlag("server-port", rootCmd.PersistentFlags().Lookup("server-port"))
	if err != nil {
		log.Logger.Error(err.Error())
		os.Exit(1)
	}
}
