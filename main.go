package main

import (
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/contrib/ginrus"
	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
	"github.com/mahtuag/jwtplay/routes/jwtplay"
	"github.com/mahtuag/jwtplay/utils"
	toml "github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"
)

func main() {
	configFile := flag.String("configFile", "", "config file to use")
	flag.Parse()

	if len(*configFile) == 0 {
		pwd, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		*configFile = filepath.Join(pwd, "config.toml")
	}

	config, err := toml.LoadFile(*configFile)
	if err != nil {
		panic(err)
	}

	ginMode := config.Get("server.gin_mode").(string)
	gin.SetMode(ginMode)

	logLevel := config.Get("logger.level").(int64)
	logger := log.New()
	logger.Out = os.Stdout
	logger.Formatter = &log.JSONFormatter{}
	logger.Level = log.Level(logLevel)
	utils.SetLogger(logger)
	logMiddleware := ginrus.Ginrus(utils.GetLogger(), time.RFC3339Nano, true)

	// Load initial auth secret from config
	authSecretFile := config.Get("jwt.secret").(string)
	authSecret, err := ioutil.ReadFile(authSecretFile)
	if err != nil {
		panic(err)
	}
	authSecretString := string(authSecret)
	logger.WithField("authSecret", authSecretString).Info("have read auth secret")
	auth.SetSecret(authSecretString)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logMiddleware)

	authtestGroup := router.Group("/jwtplay")
	jwtplay.Init(authtestGroup)

	port := config.Get("server.port").(string)
	err = router.Run(port)
	if err != nil {
		panic(err)
	}
}
