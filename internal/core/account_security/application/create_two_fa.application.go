package account_security_applications

import "context"

func (app *Application) CreateTwoFA(ctx context.Context, userId, identifier, issuer string) (string, string, []byte, error) {
	secret, qrUrl, qrImg, err := app.OTPAdapter.Config2fa(issuer, identifier)
	if err != nil {
		return "", "", []byte{}, err
	}

	if err := app.Repository.UpsertTwoFA(ctx, userId, secret, issuer); err != nil {
		return "", "", []byte{}, err
	}

	return secret, qrUrl, qrImg, nil
}
