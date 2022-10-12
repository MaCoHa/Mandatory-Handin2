package main

import (
	pb "Mandatory-Handin2/netprotocols"
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"google.golang.org/grpc"
)

var AlicePrivateSignKey *ecdsa.PrivateKey
var BobsPublicSignKey *ecdsa.PublicKey

var client pb.DicegameprotocolsClient
var ctx context.Context
var user string

var serverPort = "localhost:6060"

func main() {

	conn, err := grpc.Dial(serverPort, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			panic(err)

		}
	}(conn)

	client = pb.NewDicegameprotocolsClient(conn)

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	for {
		user = ""
		fmt.Println("write anything to throw dice with Bob:")
		fmt.Scan(&user)
		if user != "" {
			// TODO: implemente alice comitment and respons potocol
		}
	}

}
