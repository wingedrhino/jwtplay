package jwtplay

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/secrets"
	"github.com/pkg/errors"
)

// SetSecret sets the secret used to sign the token
func SetSecret(c *gin.Context) {
	var i = struct {
		Symmetric  string `json:"symmetric" binding:"required"`
		PrivateKey string `json:"private_key" binding:"required"`
		PublicKey  string `json:"public_key" binding:"required"`
	}{}
	err := c.BindJSON(&i)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", errors.Wrap(err, "Unable to parse request body as JSON")),
		})
	}
	secrets.SetSym(i.Symmetric)
	secrets.SetAsym(i.PublicKey, i.PrivateKey)
	c.JSON(http.StatusOK, i)
}
