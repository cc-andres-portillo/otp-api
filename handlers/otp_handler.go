package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/cc-andres-portillo/otp-api/services"
)

type GenerateRequest struct {
	Username string `json:"username" binding:"required"`
	Issuer   string `json:"issuer" binding:"required"`
}

type ValidateRequest struct {
	Token   string `json:"token" binding:"required"`
	Secret  string `json:"secret" binding:"required"`
}

func GenerateOTP(c *gin.Context) {
	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	result, err := services.GenerateOTP(req.Username, req.Issuer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	c.JSON(http.StatusOK, result)
}

func ValidateOTP(c *gin.Context) {
	var req ValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	valid := services.ValidateOTP(req.Secret, req.Token)
	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func GetMockToken(c *gin.Context) {
	type Request struct {
		Secret string `json:"secret"`
	}

	var req Request
	if err := c.ShouldBindJSON(&req); err != nil || req.Secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing secret"})
		return
	}

	// Generar token válido para 90 segundos
	token, err := totp.GenerateCodeCustom(req.Secret, time.Now(), totp.ValidateOpts{
		Period:    90,
		Skew:      0,
		Digits:    otp.DigitsSix,         // ← Usar otp.DigitsSix
		Algorithm: otp.AlgorithmSHA1,     // ← Usar otp.AlgorithmSHA1
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
