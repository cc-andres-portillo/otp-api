package user_ports

import (
	"context"

	user_domains "github.com/cc-andres-portillo/otp-api/internal/core/user"
)

type ApplicationPort interface {
	GetByID(ctx context.Context, id string) (*user_domains.User, error)
	GetByEmail(ctx context.Context, email string) (*user_domains.User, error)
	SetTwoFAById(ctx context.Context, userId string, active bool) error
}
