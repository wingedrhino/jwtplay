package jwtplay

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
	"github.com/pkg/errors"
)

// SetSecret sets the secret used to sign the token
func SetSecret(c *gin.Context) {
	var i = struct {
		Secret string `json:"secret" binding:"required"`
	}{}
	err := c.BindJSON(&i)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", errors.Wrap(err, "Unable to parse request body as JSON")),
		})
	}
	auth.SetSecret(i.Secret)
	c.JSON(http.StatusOK, i)
}
