package account_security_applications

import (
	"context"
	"errors"
	"fmt"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
)

func (app *Application) VerifyTwoFAByToken(ctx context.Context, userId, token string) (*accountsecurity_domains.AccountSecurity, error) {
	security, err := app.Repository.GetByUserID(ctx, userId, accountsecurity_domains.AccountSecurity_OTP)
	if err != nil {
		return nil, err
	}

	fmt.Println(security)

	if !app.OTPAdapter.Validate(security.OTP.Secret, token) {
		return nil, errors.New("INVALID_TOKEN")
	}

	return security, nil
}
