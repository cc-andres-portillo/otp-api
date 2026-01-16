package account_security_mongocc

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
	"go.mongodb.org/mongo-driver/bson"
)

func (r *Repository) HardDeleteTwoFAByUserID(ctx context.Context, userId string, t accountsecurity_domains.AccountSecurityType) error {
	_, err := r.DB.Collection(CollectionName).DeleteOne(ctx, bson.M{"userId": userId, "type": t})
	if err != nil {
		return err
	}

	return nil
}
