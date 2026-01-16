package user_mongocc

import (
	"go.mongodb.org/mongo-driver/mongo"
)

const CollectionName = "profile"

type Repository struct {
	DB *mongo.Database
}
