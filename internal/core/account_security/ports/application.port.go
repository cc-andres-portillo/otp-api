package account_security_ports

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
)

type ApplicationPort interface {
	CreateTwoFA(ctx context.Context, userId, identifier, issuer string) (string, string, []byte, error)
	CreateRecoveryCodes(ctx context.Context, userId string) ([]string, error)
	VerifyTwoFAByToken(ctx context.Context, userId, token string) (*accountsecurity_domains.AccountSecurity, error)
	DeleteTwoFAByUserID(ctx context.Context, userId string) error
	UseRecoveryCode(ctx context.Context, userId, code string) error
}
