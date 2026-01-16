package user_applications

import "context"

func (app *Application) SetTwoFAById(ctx context.Context, userId string, active bool) error {
	return app.Repository.UpdateTwoFAById(ctx, userId, active)
}
