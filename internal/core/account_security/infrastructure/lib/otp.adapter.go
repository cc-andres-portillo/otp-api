package auth_security_libs

import (
	"bytes"
	"errors"
	"image/png"
	"time"

	pquerna_otp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	account_security_ports "github.com/cc-andres-portillo/otp-api/internal/core/account_security/ports"
)

type otpAdapter struct {
	period, skew, secretSize uint
	digits                   pquerna_otp.Digits
	algorithm                pquerna_otp.Algorithm
}

func New(period uint) account_security_ports.OTPAdapterPort {
	if period == 0 {
		return otpDisableAdapter{}
	}
	return &otpAdapter{
		period:     period,
		skew:       1,
		secretSize: 20,
		digits:     pquerna_otp.DigitsSix,
		algorithm:  pquerna_otp.AlgorithmSHA1,
	}
}

func (o otpAdapter) IsEnabled() bool {
	return true
}

func (o otpAdapter) Config(issuer, accountName string) (string, string, []byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      o.period,
		Digits:      o.digits,
		Algorithm:   o.algorithm,
		SecretSize:  o.secretSize,
	})
	if err != nil {
		return "", "", nil, errors.New("Error generando clave OTP")
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", nil, err
	}
	if err := png.Encode(&buf, img); err != nil {
		return "", "", nil, err
	}

	return key.Secret(), key.URL(), buf.Bytes(), nil
}

func (o otpAdapter) Validate(secret, token string) bool {
	valid, err := totp.ValidateCustom(token, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    o.period,
		Skew:      o.skew,
		Digits:    o.digits,
		Algorithm: o.algorithm,
	})
	return err == nil && valid
}
