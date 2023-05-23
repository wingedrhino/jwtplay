package jwtplay

import (
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/mahtuag/jwtplay/auth"
	"github.com/pkg/errors"
)

// GetToken to obtain JWT token
func GetToken(c *gin.Context) {
	var i = struct {
		Email string `json:"email" binding:"required"`
		Alg   string `json:"alg" binding:"required"`
	}{}
	err := c.BindJSON(&i)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%+v", errors.Wrap(err, "Unable to parse request body as JSON")),
		})
	}
	claims := jwt.MapClaims{
		"email":          i.Email,
		"email_verified": true,
	}
	tokenString, err := auth.GetToken(claims, i.Alg)
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
