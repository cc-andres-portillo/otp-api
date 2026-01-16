package auth_security_libs

import (
	"bytes"
	"errors"
	"image/png"
	"time"

	pquerna_otp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type otp struct {
	Period uint
}

func NewOptAdapter(period uint) *otp {
	return &otp{Period: period}
}

func (o *otp) Config2fa(issuer, accountName string) (string, string, []byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      o.Period,
	})
	if err != nil {
		return "", "", nil, errors.New("Error generando clave OTP")
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", nil, err
	}
	png.Encode(&buf, img)

	return key.Secret(), key.URL(), buf.Bytes(), nil
}

func (o *otp) ValidateCode(userCode string, secretoGuardado string) bool {
	// Validate comprueba el código contra el secreto.
	// Usa la hora actual del servidor.
	return totp.Validate(userCode, secretoGuardado)
}

func (o *otp) ValidateOTP(secret, token string) bool {
	valid, err := totp.ValidateCustom(token, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    pquerna_otp.DigitsSix,
		Algorithm: pquerna_otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
