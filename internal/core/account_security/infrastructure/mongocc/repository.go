package account_security_mongocc

import (
	"go.mongodb.org/mongo-driver/mongo"
)

const CollectionName = "account_security"

type Repository struct {
	DB *mongo.Database
}
