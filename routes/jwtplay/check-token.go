package jwtplay

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
)

// CheckToken checks if a token is valid using the `github.com/dgrijalva/jwt-go`
// package.
func CheckToken(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	token, err := auth.ParseToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", err),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	}
}
