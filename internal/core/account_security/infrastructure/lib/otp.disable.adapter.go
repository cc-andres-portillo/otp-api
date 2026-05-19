package auth_security_libs

import otp_adapter_ports "github.com/cc-andres-portillo/otp-api/internal/core/account_security/ports"

type otpDisableAdapter struct{}

func (otpDisableAdapter) IsEnabled() bool {
	return false
}

func (otpDisableAdapter) Config(_, _ string) (otp_adapter_ports.OTPConfig, error) {
	return otp_adapter_ports.OTPConfig{}, nil
}

func (otpDisableAdapter) Validate(_, _ string) bool {
	return false
}
