package account_security_mongocc

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (r *Repository) UpsertTwoFA(ctx context.Context, userId, secret, issuer string) error {
	filter := bson.M{"userId": userId, "otp.issuer": issuer}
	account_security := accountsecurity_domains.AccountSecurity{
		UserID: userId,
		Type:   accountsecurity_domains.AccountSecurity_OTP,
		OTP: accountsecurity_domains.SecurityOTP{
			Secret: secret,
			Issuer: issuer,
		},
	}

	account_security = *account_security.New()

	update := bson.M{
		"$set": bson.M{
			"otp.secret": secret,
			"updatedAt":  account_security.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"_id":        account_security.ID,
			"userId":     userId,
			"type":       account_security.Type,
			"otp.issuer": issuer,
			"createdAt":  account_security.CreatedAt,
			"isRemoved":  account_security.IsRemoved,
		},
	}

	opts := options.Update().SetUpsert(true)

	if _, err := r.DB.Collection(CollectionName).UpdateOne(ctx, filter, update, opts); err != nil {
		return err
	}

	return nil
}
