package common

import (
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.Logger

func init() {
	core := zapcore.NewCore(getEcoder(), zapcore.AddSync(getWriter()), zapcore.InfoLevel)
	Logger = zap.New(core, zap.AddCaller())
}

func getEcoder() zapcore.Encoder {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000")
	config.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewConsoleEncoder(config)
}

func getWriter() io.Writer {
	logFile := "./ktun.log"
	logF, _ := os.OpenFile(logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	return io.MultiWriter(os.Stdout, logF)
}
