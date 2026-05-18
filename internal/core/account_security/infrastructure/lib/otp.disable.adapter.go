package auth_security_libs

type otpDisableAdapter struct{}

func (otpDisableAdapter) IsEnabled() bool {
	return false
}

func (otpDisableAdapter) Config(_, _ string) (string, string, []byte, error) {
	return "", "", []byte(""), nil
}

func (otpDisableAdapter) Validate(_, _ string) bool {
	return false
}
