package services

import (
	"encoding/base64"

	"github.com/pquerna/otp/totp"
	"github.com/cc-andres-portillo/otp-api/utils"
)

type OTPResult struct {
	Secret          string   `json:"secret"`
	OTPAuthURL      string   `json:"otpauth_url"`
	QRCodeBase64    string   `json:"qr_code_base64"`
	RecoveryCodes   []string `json:"recovery_codes"`
}

func GenerateOTP(username, issuer string) (*OTPResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
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

	// Generar códigos de recuperación (5)
	recovery := utils.GenerateRecoveryCodes(5)

	return &OTPResult{
		Secret:        key.Secret(),
		OTPAuthURL:    key.URL(),
		QRCodeBase64:  qrBase64,
		RecoveryCodes: recovery,
	}, nil
}

func ValidateOTP(secret, token string) bool {
	valid := totp.Validate(token, secret)
	return valid
}
