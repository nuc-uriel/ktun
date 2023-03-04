package cmd

import (
	"context"
	"ktun/common"
	"ktun/server"
	"net"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// serverUpCmd represents the serve command
var serverUpCmd = &cobra.Command{
	Use:   "up",
	Short: "服务器端启动",
	Run: func(cmd *cobra.Command, args []string) {
		daemon := viper.GetBool("server.daemon")
		tcpAddr := viper.GetString("server.tcp")
		name := viper.GetString("server.name")
		ipCidr := viper.GetString("server.ipcidr")
		outDev := viper.GetString("server.outdev")
		if daemon {
			if _, err := net.Dial("tcp", tcpAddr); err == nil {
				common.Logger.Fatal("服务启动失败, TCP服务端口被占用")
			}
			command := exec.Command(os.Args[0], "server", "up", "-t", tcpAddr, "-n", name, "-i", ipCidr, "--daemon=false")
			err := command.Start()
			if err != nil {
				common.Logger.Fatal("服务启动失败", zap.Error(err))
			}
			common.Logger.Info("服务启动成功", zap.String("cmd", command.String()), zap.Int("pid", command.Process.Pid))
			path := "/run/lock"
			if _, err = os.Stat(path); err != nil && !os.IsExist(err) {
				os.Mkdir(path, 0777)
			}
			os.WriteFile(path+"/ktuns.lock", []byte(strconv.Itoa(command.Process.Pid)), 0666)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go common.WatchExit(ctx, cancel)
		server.New(ctx, cancel, tcpAddr, name, ipCidr, outDev).Run()
	},
}

func init() {
	serverCmd.AddCommand(serverUpCmd)
	serverUpCmd.Flags().StringP("tcp", "t", "0.0.0.0:7890", "TCP服务地址, 如: 0.0.0.0:7890")
	serverUpCmd.Flags().StringP("name", "n", "tun0", "TUN设备名称, 如: tun0")
	serverUpCmd.Flags().StringP("ipcidr", "i", "10.0.10.1/24", "TUN设备IP地址, 如: 10.0.10.1/24")
	serverUpCmd.Flags().StringP("outdev", "o", "eth0", "出口设备端口")
	serverUpCmd.Flags().BoolP("daemon", "d", false, "后台启动服务")
	viper.BindPFlag("server.tcp", serverUpCmd.Flags().Lookup("tcp"))
	viper.BindPFlag("server.name", serverUpCmd.Flags().Lookup("name"))
	viper.BindPFlag("server.ipcidr", serverUpCmd.Flags().Lookup("ipcidr"))
	viper.BindPFlag("server.daemon", serverUpCmd.Flags().Lookup("daemon"))
	viper.BindPFlag("server.outdev", serverUpCmd.Flags().Lookup("outdev"))
}
