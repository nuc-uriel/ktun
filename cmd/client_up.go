package cmd

import (
	"context"
	"ktun/client"
	"ktun/common"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// clientUpCmd represents the serve command
var clientUpCmd = &cobra.Command{
	Use:   "up",
	Short: "启动客户端",
	Run: func(cmd *cobra.Command, args []string) {
		tcpAddr := viper.GetString("client.tcp")
		count := viper.GetInt("client.count")
		daemon := viper.GetBool("client.daemon")
		if daemon {
			command := exec.Command(os.Args[0], "client", "up", "-t", tcpAddr, "--daemon=false")
			err := command.Start()
			if err != nil {
				common.Logger.Fatal("客户端启动失败", zap.Error(err))
			}
			common.Logger.Info("客户端启动成功", zap.String("cmd", command.String()), zap.Int("pid", command.Process.Pid))
			path := "/run/lock"
			if _, err = os.Stat(path); err != nil && !os.IsExist(err) {
				os.Mkdir(path, 0777)
			}
			os.WriteFile(path+"/ktunc.lock", []byte(strconv.Itoa(command.Process.Pid)), 0666)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go common.WatchExit(ctx, cancel)
		client.New(ctx, cancel, tcpAddr).Run(count)
	},
}

func init() {
	clientCmd.AddCommand(clientUpCmd)
	clientUpCmd.Flags().StringP("tcp", "t", "11.11.11.11:7890", "TCP服务地址, 如: 11.11.11.11:7890")
	clientUpCmd.Flags().IntP("count", "u", 10, "服务器连接协程数, 如: 10")
	clientUpCmd.Flags().BoolP("daemon", "d", false, "后台启动服务")
	viper.BindPFlag("client.tcp", clientUpCmd.Flags().Lookup("tcp"))
	viper.BindPFlag("client.count", clientUpCmd.Flags().Lookup("count"))
	viper.BindPFlag("client.daemon", clientUpCmd.Flags().Lookup("daemon"))
}
