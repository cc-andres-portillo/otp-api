package main

import (
	"github.com/gin-gonic/gin"
	"github.com/cc-andres-portillo/otp-api/handlers"
)

func main() {
	r := gin.Default()

	r.POST("/otp/generate", handlers.GenerateOTP)
	r.POST("/otp/validate", handlers.ValidateOTP)
	r.POST("/otp/mock-token", handlers.GetMockToken)

	r.Run(":8080") // http://localhost:8080
}