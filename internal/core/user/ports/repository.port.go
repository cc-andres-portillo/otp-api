package user_ports

import (
	"context"

	user_domains "github.com/cc-andres-portillo/otp-api/internal/core/user"
)

type RepositoryPort interface {
	GetByID(ctx context.Context, id string) (*user_domains.User, error)
	GetByEmail(ctx context.Context, email string) (*user_domains.User, error)
	UpdateTwoFAById(ctx context.Context, userId string, active bool) error
}
