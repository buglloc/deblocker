package commands

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/buglloc/deblocker/internal/config"
)

var (
	cfgPath string
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:           "deblockerd",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         `DeBlocker is a sites rechecker and eBPG exporter from f*cking internet censorship`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(
		initConfig,
		initLogger,
	)

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&cfgPath, "cfg", "", "config file")

	rootCmd.AddCommand(
		startCmd,
	)
}

func initConfig() {
	var err error
	cfg, err = config.LoadConfig(cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "unable to load config: %v\n", err)
		os.Exit(1)
	}
}

func initLogger() {
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
