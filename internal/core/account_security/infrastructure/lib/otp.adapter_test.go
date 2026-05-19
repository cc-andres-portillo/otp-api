package auth_security_libs

import (
	"bytes"
	"errors"
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

// Secret base32 fijo y conocido: hace 100% deterministas los tests que comparan
// códigos entre períodos distintos (sin depender del secret aleatorio de Config).
const testSecret = "JBSWY3DPEHPK3PXP"

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
	farPrev, _ := totp.GenerateCodeCustom(cfg.Secret, testBase.Add(-60*time.Second), testOpts)
	farNext, _ := totp.GenerateCodeCustom(cfg.Secret, testBase.Add(60*time.Second), testOpts)
	old, _ := totp.GenerateCodeCustom(cfg.Secret, testBase.Add(-90*time.Second), testOpts)

	if !a.validateAt(cfg.Secret, prev, testBase) {
		t.Error("Skew=1 debe aceptar la ventana anterior (-30s)")
	}
	if !a.validateAt(cfg.Secret, next, testBase) {
		t.Error("Skew=1 debe aceptar la ventana siguiente (+30s)")
	}
	if a.validateAt(cfg.Secret, farPrev, testBase) {
		t.Error("Skew=1 debe rechazar 2 ventanas atrás (-60s)")
	}
	if a.validateAt(cfg.Secret, farNext, testBase) {
		t.Error("Skew=1 debe rechazar 2 ventanas adelante (+60s)")
	}
	if a.validateAt(cfg.Secret, old, testBase) {
		t.Error("ventana lejana (-90s) debe rechazarse")
	}
}

func TestConfigEmptyArgs(t *testing.T) {
	a := newTestAdapter(t)

	_, err := a.Config("", "")
	if err == nil {
		t.Fatal(`Config("", "") debería devolver error`)
	}
	if !errors.Is(err, ErrOTPKeyGeneration) {
		t.Errorf("el error debería matchear ErrOTPKeyGeneration, got %v", err)
	}
}

func TestDisableAdapter(t *testing.T) {
	d := New(0) // period 0 ⇒ otpDisableAdapter

	if d.IsEnabled() {
		t.Error("New(0).IsEnabled() debería ser false")
	}

	cfg, err := d.Config("MiApp", "user@mail.com")
	if err != nil {
		t.Errorf("disable Config no debería devolver error, got %v", err)
	}
	if cfg.Secret != "" || cfg.URL != "" || len(cfg.QRImg) != 0 {
		t.Errorf("disable Config debería devolver OTPConfig vacío, got %+v", cfg)
	}

	if d.Validate(testSecret, "123456") {
		t.Error("disable Validate debería ser siempre false")
	}
}

func TestPeriodFromStruct(t *testing.T) {
	a60, ok := New(60).(*otpAdapter)
	if !ok {
		t.Fatalf("New(60) no devolvió *otpAdapter")
	}

	opts60 := totp.ValidateOpts{
		Period:    60,
		Digits:    pquerna_otp.DigitsSix,
		Algorithm: pquerna_otp.AlgorithmSHA1,
	}
	code60, err := totp.GenerateCodeCustom(testSecret, testBase, opts60)
	if err != nil {
		t.Fatalf("GenerateCodeCustom (period 60): %v", err)
	}
	code30, err := totp.GenerateCodeCustom(testSecret, testBase, testOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom (period 30): %v", err)
	}

	if !a60.validateAt(testSecret, code60, testBase) {
		t.Error("adapter period=60 debe validar un código generado con period=60")
	}
	if a60.validateAt(testSecret, code30, testBase) {
		t.Error("adapter period=60 no debe validar un código de period=30 (el período viene del struct)")
	}
}

func TestValidatePublicRoundTrip(t *testing.T) {
	a := newTestAdapter(t)

	cfg, err := a.Config("MiApp", "user@mail.com")
	if err != nil {
		t.Fatalf("Config devolvió error: %v", err)
	}

	code, err := totp.GenerateCode(cfg.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !a.Validate(cfg.Secret, code) {
		t.Error("Validate debería aceptar un código generado para el momento actual")
	}
	if a.Validate(cfg.Secret, "000000") {
		t.Error("Validate no debería aceptar un código inválido")
	}
}
