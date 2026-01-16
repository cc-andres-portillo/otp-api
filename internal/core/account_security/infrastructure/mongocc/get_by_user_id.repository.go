package account_security_mongocc

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
	"go.mongodb.org/mongo-driver/bson"
)

func (r *Repository) GetByUserID(ctx context.Context, userId string, t accountsecurity_domains.AccountSecurityType) (*accountsecurity_domains.AccountSecurity, error) {
	var security accountsecurity_domains.AccountSecurity
	err := r.DB.Collection(CollectionName).FindOne(ctx, bson.M{"userId": userId, "type": t}).Decode(&security)
	if err != nil {
		return nil, err
	}

	return &security, nil
}
