package user_applications

import user_ports "github.com/cc-andres-portillo/otp-api/internal/core/user/ports"

type Application struct {
	Repository user_ports.RepositoryPort
}
