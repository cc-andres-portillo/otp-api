package account_security_applications

import (
	"context"
	"errors"
)

func (app *Application) CreateTwoFA(ctx context.Context, userId, identifier, issuer string) (string, string, []byte, error) {
	if !app.OTPAdapter.IsEnabled() {
		return "", "", []byte{}, errors.New("TWO_FA_NOT_ENABLED")
	}

	cfg, err := app.OTPAdapter.Config(issuer, identifier)
	if err != nil {
		return "", "", []byte{}, err
	}

	if err := app.Repository.UpsertTwoFA(ctx, userId, cfg.Secret, issuer); err != nil {
		return "", "", []byte{}, err
	}

	return cfg.Secret, cfg.URL, cfg.QRImg, nil
}
