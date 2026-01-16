package account_security_ports

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
)

type RepositoryPort interface {
	UpsertTwoFA(ctx context.Context, userId, secret, issuer string) error
	UpsertRecoveryCodes(ctx context.Context, userId string, codes []string) error
	GetByUserID(ctx context.Context, userId string, t accountsecurity_domains.AccountSecurityType) (*accountsecurity_domains.AccountSecurity, error)
	HardDeleteTwoFAByUserID(ctx context.Context, userId string, t accountsecurity_domains.AccountSecurityType) error
	ValidateRecoveryCode(ctx context.Context, userId, code string) error
	SetUsedRecoveryCode(ctx context.Context, userId, code string) error
}
