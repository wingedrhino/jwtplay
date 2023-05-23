package jwtplay

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
)

// GetTokenBody to obtain JWT token that's a signed version of request body
func GetTokenBody(c *gin.Context) {
	claims := auth.SimpleClaims{}
	err := claims.FromReader(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", err),
		})
		return
	}
	tokenString, err := auth.GetToken(claims)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", err),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
		})
	}
}
