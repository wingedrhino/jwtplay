package jwtplay

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// DecodeB64 is a helper to decode Base64 strings
func DecodeB64(c *gin.Context) {
	var i = struct {
		Encoded string `json:"encoded" binding:"required"`
	}{}
	err := c.BindJSON(&i)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", errors.Wrap(err, "Unable to parse request body as JSON")),
		})
	}
	decoded, err := base64.RawURLEncoding.DecodeString(i.Encoded)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", errors.Wrap(err, "unable to decode base644")),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"decoded": decoded,
	})
}
