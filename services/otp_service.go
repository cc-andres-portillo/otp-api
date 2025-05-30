package services

import (
	"encoding/base64"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/cc-andres-portillo/otp-api/utils"
)

type OTPResult struct {
	Secret        string   `json:"secret"`
	OTPAuthURL    string   `json:"otpauth_url"`
	QRCodeBase64  string   `json:"qr_code_base64"`
	RecoveryCodes []string `json:"recovery_codes"`
}

func GenerateOTP(username, issuer string) (*OTPResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
		Period:      90, // ← ⚠️ Tiempo de expiración del token en segundos
	})
	if err != nil {
		return nil, err
	}

	// Generar código QR en base64
	qrBytes, err := utils.GenerateQRCode(key.URL())
	if err != nil {
		return nil, err
	}
	qrBase64 := base64.StdEncoding.EncodeToString(qrBytes)

	// Generar códigos de recuperación
	recovery := utils.GenerateRecoveryCodes(5)

	return &OTPResult{
		Secret:        key.Secret(),
		OTPAuthURL:    key.URL(),
		QRCodeBase64:  qrBase64,
		RecoveryCodes: recovery,
	}, nil
}

func ValidateOTP(secret, token string) bool {
	// Usar la misma configuración para validar el OTP generado con Period=90
	valid, err := totp.ValidateCustom(token, secret, time.Now(), totp.ValidateOpts{
		Period:    90,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	// Si hay error, el token no es válido
	if err != nil {
		return false
	}

	return valid
}
