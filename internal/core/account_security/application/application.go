package account_security_applications

import (
	account_security_ports "github.com/cc-andres-portillo/otp-api/internal/core/account_security/ports"
)

type Application struct {
	Repository account_security_ports.RepositoryPort
	OTPAdapter account_security_ports.OTPAdapterPort
}
