package utils

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRecoveryCodes genera n códigos de recuperación aleatorios
func GenerateRecoveryCodes(n int) []string {
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		codes[i] = generateCode(8) // 8 caracteres hexadecimales
	}
	return codes
}

func generateCode(length int) string {
	b := make([]byte, length/2) // cada byte = 2 caracteres hex
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
