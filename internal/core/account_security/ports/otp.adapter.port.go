package account_security_ports

type OTPAdapterPort interface {
	IsEnabled() bool
	Config(issuer, accountName string) (secret, url string, qrImg []byte, err error)
	Validate(secret, token string) bool
}
