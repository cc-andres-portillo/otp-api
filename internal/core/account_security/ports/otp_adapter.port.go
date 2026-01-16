package account_security_ports

type OTPAdapterPort interface {
	Config2fa(issuer, accountName string) (secret, url string, qrImg []byte, err error)
	ValidateCode(userCode string, secretoGuardado string) bool
	ValidateOTP(secret, token string) bool
}
