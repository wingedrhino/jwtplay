package utils

import (
	log "github.com/sirupsen/logrus"
)

var logger *log.Logger

// SetLogger sets a Logrus logger
func SetLogger(l *log.Logger) {
	logger = l
}

// GetLogger returns a Logrus logger
func GetLogger() *log.Logger {
	return logger
}
