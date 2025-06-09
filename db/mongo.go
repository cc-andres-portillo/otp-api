package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client
var DB *mongo.Database

func ConnectMongo() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI("mongodb://root:12345abc@localhost:27017/?directConnection=true&authMechanism=SCRAM-SHA-1&authSource=admin")
	var err error
	Client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Error conectando a MongoDB:", err)
	}
	DB = Client.Database("futurapps")
	log.Println("Conectado a MongoDB")
}

func GetCollection(name string) *mongo.Collection {
	return DB.Collection(name)
}
