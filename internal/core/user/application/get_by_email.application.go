package user_applications

import (
	"context"

	user_domains "github.com/cc-andres-portillo/otp-api/internal/core/user"
)

func (app *Application) GetByEmail(ctx context.Context, email string) (*user_domains.User, error) {
	user, err := app.Repository.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return user, nil
}
