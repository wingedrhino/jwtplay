package jwtplay

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
	"github.com/pkg/errors"
)

// CheckTokenJWKS checks if a token is valid using `github.com/square/go-jose`.
// It also additionally decodes the claims section into plain JSON.
func CheckTokenJWKS(c *gin.Context) {
	var i = struct {
		Token string `json:"token" binding:"required"`
		JWKS  string `json:"jwks" binding:"required"`
	}{}
	err := c.BindJSON(&i)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", errors.Wrap(err, "Unable to parse request body as JSON")),
		})
	}
	token, err := auth.VerifyJWKS(i.Token, i.JWKS)
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"err":   fmt.Sprintf("%+v", err),
	})
}
