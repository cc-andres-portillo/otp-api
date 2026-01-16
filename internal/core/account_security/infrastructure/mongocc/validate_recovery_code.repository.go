package account_security_mongocc

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
	"go.mongodb.org/mongo-driver/bson"
)

func (r *Repository) ValidateRecoveryCode(ctx context.Context, userId, code string) error {
	var security accountsecurity_domains.AccountSecurity
	err := r.DB.Collection(CollectionName).FindOne(ctx, bson.M{"userId": userId, "recoveryCodes.available": code}).Decode(&security)
	if err != nil {
		return err
	}

	return nil
}
