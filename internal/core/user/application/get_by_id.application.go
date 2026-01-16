package user_applications

import (
	"context"

	user_domains "github.com/cc-andres-portillo/otp-api/internal/core/user"
)

func (app *Application) GetByID(ctx context.Context, id string) (*user_domains.User, error) {
	user, err := app.Repository.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}
