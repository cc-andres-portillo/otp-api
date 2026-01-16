package account_security_applications

import (
	"context"
)

func (app *Application) UseRecoveryCode(ctx context.Context, userId, code string) error {
	if err := app.Repository.ValidateRecoveryCode(ctx, userId, code); err != nil {
		return err
	}

	if err := app.Repository.SetUsedRecoveryCode(ctx, userId, code); err != nil {
		return err
	}

	return nil
}
