package log

import (
	"log"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.SugaredLogger = initLogger(false)

func initLogger(enableStackTrace bool) *zap.SugaredLogger {
	config := zap.NewProductionEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder

	fileEncoder := zapcore.NewJSONEncoder(config)
	stdoutEncoder := zapcore.NewConsoleEncoder(config)

	// FIXME read from env variable
	logFile, err := os.OpenFile(
		"github-analyzer.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if err != nil {
		log.Fatal(err)
	}

	writer := zapcore.AddSync(logFile)
	defaultLogLevel := zapcore.DebugLevel

	core := zapcore.NewTee(
		zapcore.NewCore(
			stdoutEncoder,
			zapcore.AddSync(os.Stdout),
			defaultLogLevel,
		),
		zapcore.NewCore(fileEncoder, writer, defaultLogLevel),
	)

	if enableStackTrace {
		return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)).
			Sugar()
	}
	return zap.New(core, zap.AddCaller()).Sugar()
}
