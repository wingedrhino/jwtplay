package jwtplay

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
)

// CheckToken checks if a token is valid using the `github.com/dgrijalva/jwt-go`
// package. It also additionally decodes the claims section into plain JSON.
func CheckToken(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	token, errValid := auth.ValidateToken(tokenString)
	claims, errClaims := auth.ParseClaims(tokenString)
	c.JSON(http.StatusOK, gin.H{
		"token":        token,
		"error_token":  fmt.Sprintf("%+v", errValid),
		"claims":       claims,
		"error_claims": fmt.Sprintf("%+v", errClaims),
	})
}
