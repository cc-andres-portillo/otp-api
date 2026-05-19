package auth_security_libs

import (
	"bytes"
	"image/png"
	"testing"
	"time"

	pquerna_otp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Tiempo fijo + opts que deben coincidir con lo que arma New(30): los tests son
// deterministas (no usan time.Now()), por eso el refactor validateAt(t time.Time).
var (
	testBase = time.Unix(1_700_000_000, 0)
	testOpts = totp.ValidateOpts{
		Period:    30,
		Digits:    pquerna_otp.DigitsSix,
		Algorithm: pquerna_otp.AlgorithmSHA1,
	}
)

func newTestAdapter(t *testing.T) *otpAdapter {
	t.Helper()
	a, ok := New(30).(*otpAdapter)
	if !ok {
		t.Fatalf("New(30) no devolvió *otpAdapter")
	}
	return a
}

func TestConfigRoundTrip(t *testing.T) {
	a := newTestAdapter(t)

	cfg, err := a.Config("MiApp", "user@mail.com")
	if err != nil {
		t.Fatalf("Config devolvió error: %v", err)
	}

	code, err := totp.GenerateCodeCustom(cfg.Secret, testBase, testOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	if !a.validateAt(cfg.Secret, code, testBase) {
		t.Error("código recién generado debería ser válido")
	}
	if a.validateAt(cfg.Secret, "000000", testBase) {
		t.Error("código inválido no debería pasar")
	}

	other, err := a.Config("MiApp", "other@mail.com")
	if err != nil {
		t.Fatalf("Config (other) devolvió error: %v", err)
	}
	if a.validateAt(other.Secret, code, testBase) {
		t.Error("un secret distinto no debería validar el código")
	}
}

func TestConfigOutputs(t *testing.T) {
	a := newTestAdapter(t)

	cfg, err := a.Config("MiApp", "user@mail.com")
	if err != nil {
		t.Fatalf("Config devolvió error: %v", err)
	}

	if _, err := pquerna_otp.NewKeyFromURL(cfg.URL); err != nil {
		t.Errorf("URL otpauth inválida: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(cfg.QRImg)); err != nil {
		t.Errorf("QR no decodifica como PNG: %v", err)
	}
}

func TestValidateWindowSkew(t *testing.T) {
	a := newTestAdapter(t)

	cfg, err := a.Config("MiApp", "user@mail.com")
	if err != nil {
		t.Fatalf("Config devolvió error: %v", err)
	}

	prev, _ := totp.GenerateCodeCustom(cfg.Secret, testBase.Add(-30*time.Second), testOpts)
	next, _ := totp.GenerateCodeCustom(cfg.Secret, testBase.Add(30*time.Second), testOpts)
	old, _ := totp.GenerateCodeCustom(cfg.Secret, testBase.Add(-90*time.Second), testOpts)

	if !a.validateAt(cfg.Secret, prev, testBase) {
		t.Error("Skew=1 debe aceptar la ventana anterior (-30s)")
	}
	if !a.validateAt(cfg.Secret, next, testBase) {
		t.Error("Skew=1 debe aceptar la ventana siguiente (+30s)")
	}
	if a.validateAt(cfg.Secret, old, testBase) {
		t.Error("ventana lejana (-90s) debe rechazarse")
	}
}

func TestConfigEmptyArgs(t *testing.T) {
	a := newTestAdapter(t)

	if _, err := a.Config("", ""); err == nil {
		t.Error(`Config("", "") debería devolver error`)
	}
}
