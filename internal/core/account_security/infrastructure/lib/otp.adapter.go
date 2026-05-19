package auth_security_libs

import (
	"bytes"
	"fmt"
	"image/png"
	"time"

	pquerna_otp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	otp_adapter_ports "github.com/cc-andres-portillo/otp-api/internal/core/account_security/ports"
)

type otpAdapter struct {
	period, skew, secretSize uint
	digits                   pquerna_otp.Digits
	algorithm                pquerna_otp.Algorithm
}

func New(period uint) otp_adapter_ports.OTPAdapterPort {
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

func (o otpAdapter) Config(issuer, accountName string) (otp_adapter_ports.OTPConfig, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      o.period,
		Digits:      o.digits,
		Algorithm:   o.algorithm,
		SecretSize:  o.secretSize,
	})
	if err != nil {
		return otp_adapter_ports.OTPConfig{}, fmt.Errorf("error generando clave OTP: %w", err)
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return otp_adapter_ports.OTPConfig{}, fmt.Errorf("generando imagen qr: %w", err)
	}
	if err := png.Encode(&buf, img); err != nil {
		return otp_adapter_ports.OTPConfig{}, fmt.Errorf("codificando png: %w", err)
	}

	return otp_adapter_ports.OTPConfig{
		Secret: key.Secret(),
		URL:    key.URL(),
		QRImg:  buf.Bytes(),
	}, nil
}

func (o otpAdapter) validateAt(secret, token string, t time.Time) bool {
	valid, err := totp.ValidateCustom(token, secret, t, totp.ValidateOpts{
		Period:    o.period,
		Skew:      o.skew,
		Digits:    o.digits,
		Algorithm: o.algorithm,
	})
	return err == nil && valid
}

func (o otpAdapter) Validate(secret, token string) bool {
	return o.validateAt(secret, token, time.Now().UTC())
}
