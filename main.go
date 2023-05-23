package main

import (
	"flag"
	"os"
	"time"

	"github.com/gin-gonic/contrib/ginrus"
	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/routes/jwtplay"
	"github.com/mahtuag/jwtplay/utils"
	log "github.com/sirupsen/logrus"
)

func main() {
	port := flag.String("port", ":8080", "HTTP port in the format ':8080' (8080 is default)")
	ginMode := flag.String("ginmode", "debug", "Gin mode - 'debug' (default), 'release' or 'test'")
	logLevel := flag.Int64("loglevel", 5, "log level: 0,1,2,3,4,5 => Panic, Fatal, Error, Warn, Info, Debug (default 5)")
	flag.Parse()

	gin.SetMode(*ginMode)

	logger := log.New()
	logger.Out = os.Stdout
	logger.Formatter = &log.JSONFormatter{}
	logger.Level = log.Level(*logLevel)
	utils.SetLogger(logger)
	logMiddleware := ginrus.Ginrus(utils.GetLogger(), time.RFC3339Nano, true)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logMiddleware)

	authtestGroup := router.Group("/jwtplay")
	jwtplay.Init(authtestGroup)

	err := router.Run(*port)
	if err != nil {
		panic(err)
	}
}
