package jwtplay

import (
	"github.com/gin-gonic/gin"
)

// Init sets up authtest router
func Init(r *gin.RouterGroup) {
	r.POST("/get-token", GetToken)
	r.POST("/get-token-body", GetTokenBody)
	r.POST("/check-token", CheckToken)
	r.POST("/check-token-manual", CheckTokenManual)
	r.POST("/set-secret", SetSecret)
	r.POST("/decode-b64", DecodeB64)
}
