package jwtplay

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
)

// CheckTokenManual manually checks if a JWT token is valid by computing the
// signature from header and claims sections and confirming that this signature
// matches the signature section.
func CheckTokenManual(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	claims, errClaims := auth.ParseClaims(tokenString)
	errValid := auth.VerifyManual(tokenString)
	c.JSON(http.StatusOK, gin.H{
		"claims":       claims,
		"claims_error": fmt.Sprintf("%+v", errClaims),
		"valid_error":  fmt.Sprintf("%+v", errValid),
	})
}
