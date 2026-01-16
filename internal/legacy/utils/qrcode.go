package utils

import (
	"github.com/skip2/go-qrcode"
)

// GenerateQRCode genera un código QR PNG a partir de la URL OTPAuth
func GenerateQRCode(otpURL string) ([]byte, error) {
	// Tamaño 256x256 px
	png, err := qrcode.Encode(otpURL, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return png, nil
}
