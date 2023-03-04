package cmd

import (
	"github.com/spf13/cobra"
)

// clientCmd represents the serve command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "启动客户端",
}

func init() {
	rootCmd.AddCommand(clientCmd)
}
