package user_mongocc

import (
	"context"

	user_domains "github.com/cc-andres-portillo/otp-api/internal/core/user"
	"go.mongodb.org/mongo-driver/bson"
)

func (r *Repository) GetByID(ctx context.Context, id string) (*user_domains.User, error) {
	var user user_domains.User
	err := r.DB.Collection(CollectionName).FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
