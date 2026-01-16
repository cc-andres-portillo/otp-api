package account_security_applications

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
)

func (app *Application) DeleteTwoFAByUserID(ctx context.Context, userId string) error {
	return app.Repository.HardDeleteTwoFAByUserID(ctx, userId, accountsecurity_domains.AccountSecurity_OTP)
}
