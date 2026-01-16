package account_security_applications

import (
	"context"

	"github.com/cc-andres-portillo/otp-api/internal/legacy/utils"
)

func (app *Application) CreateRecoveryCodes(ctx context.Context, userId string) ([]string, error) {
	codes := utils.GenerateRecoveryCodes(10)
	if err := app.Repository.UpsertRecoveryCodes(ctx, userId, codes); err != nil {
		return []string{}, err
	}

	return codes, nil
}
