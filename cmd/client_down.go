package cmd

import (
	"ktun/common"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// clientDownCmd represents the serve command
var clientDownCmd = &cobra.Command{
	Use:   "down",
	Short: "服务器端关闭",
	Run: func(cmd *cobra.Command, args []string) {
		path := "/run/lock/ktunc.lock"
		if _, err := os.Stat(path); err != nil && !os.IsExist(err) {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			common.Logger.Fatal("服务关闭失败", zap.Error(err))
		}
		command := exec.Command("kill", string(b))
		err = command.Run()
		if err != nil {
			common.Logger.Fatal("服务关闭失败", zap.Error(err))
		}
		os.Remove(path)
		common.Logger.Info("服务关闭成功", zap.String("cmd", command.String()))
	},
}

func init() {
	clientCmd.AddCommand(clientDownCmd)
}
