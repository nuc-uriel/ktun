package cmd

import (
	"ktun/common"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// rootCmd represents the base command when called without any subcommands
var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "ktun [client|server] [up|down] [-args]",
		Short: "golang编写的VPN实现",
		Long:  `golang编写的VPN实现, 支持配置化接入`,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		Run: func(cmd *cobra.Command, args []string) {
			mode := viper.GetString("mode")
			if mode == "client" {
				cmd.SetArgs([]string{"client", "up"})
				clientCmd.Parent().Execute()
			} else if mode == "server" {
				cmd.SetArgs([]string{"server", "up"})
				cmd.Execute()
			} else {
				cmd.SetArgs([]string{"-h"})
				cmd.Execute()
			}
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "conf", "c", "", "配置文件路径")
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cobra-demo.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		// 加载配置文件之前，设置一些配置
		viper.SetConfigName("ktun.yaml")  // 配置文件名称
		viper.SetConfigType("yaml")       // 配置文件的拓展名
		viper.AddConfigPath(".")          // 可选在当前工作空间中查找
		viper.AddConfigPath(home)         // 可设置多个搜索路径
		viper.AddConfigPath("/etc/ktun/") // 配置文件的路径
	}
	viper.AutomaticEnv()
	err := viper.ReadInConfig() // 找到并加载配置文件
	if err != nil {             // 处理错误
		common.Logger.Warn("配置文件加载错误", zap.Error(err))
	}
}
