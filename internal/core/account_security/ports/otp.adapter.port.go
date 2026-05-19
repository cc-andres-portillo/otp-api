package account_security_ports

type OTPConfig struct {
	Secret string
	URL    string
	QRImg  []byte
}

type OTPAdapterPort interface {
	IsEnabled() bool
	Config(issuer, accountName string) (config OTPConfig, err error)
	Validate(secret, token string) bool
}
