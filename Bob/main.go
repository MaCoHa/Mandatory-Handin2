package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"google.golang.org/grpc"
)

const (
	port = "localhost:8085"
)

var BobsPrivateSignKey = new(ecdsa.PrivateKey)
var AlicePublicSignKey = new(ecdsa.PublicKey)

var BobsMessage int
var AliceComitment = []byte{'G', 'E', 'E', 'K', 'S'}

type BobsDiceServer struct {
	pb.UnimplementedDicegameprotocolsServer
}

func init() {
	BobsPrivateSignKey = enc.GenPrivateKey()
}

func main() {

	lis, err := net.Listen("tcp", port)
	if err != nil {
		panic(err)
	}
	s := grpc.NewServer()
	pb.RegisterDicegameprotocolsServer(s, &BobsDiceServer{})
	fmt.Printf("server listening at %v\n", lis.Addr())
	if err := s.Serve(lis); err != nil {
		panic(err)
	}

}

func (s *BobsDiceServer) SendCommitment(ctx context.Context, rec *pb.CommitmentMessage) (*pb.Reply, error) {
	fmt.Println("+++ 1 +++")
	// Check if the message is from Alice
	AliceComitment = rec.CommitmentHash
	fmt.Printf("alice vaild ? = %t\n", enc.Valid(AlicePublicSignKey, string(rec.CommitmentHash), rec.Signature))

	BobsMessage = rand.Intn(10000)
	fmt.Printf("+++++ Bobs number %d +++++\n", BobsMessage)
	var sign = enc.Sign(BobsPrivateSignKey, []byte(strconv.Itoa(BobsMessage)))

	resp := &pb.Reply{Message: strconv.Itoa(BobsMessage), Signature: sign}
	return resp, nil
}

func (s *BobsDiceServer) SendMessage(ctx context.Context, rec *pb.ControlMessage) (*pb.Void, error) {
	fmt.Println("+++ 2 +++")
	// Check if the message is from Alice
	fmt.Printf("\nAlice valid : %t\n", enc.Valid(AlicePublicSignKey, (rec.Message+rec.Random), rec.Signature))

	if enc.Valid(AlicePublicSignKey, (rec.Message + rec.Random), rec.Signature) {
		//message is from Alice and we see if she sent the correct message and random
		var hash = enc.GetHash(rec.Message, rec.Random)

		if bytes.Compare(hash, AliceComitment) == 0 {
			fmt.Printf("Alice sent the same message as was in here commitment\n")
			AliceintVar, err := strconv.Atoi(rec.Message)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Bobs number: %d\nAlice number %d\n", BobsMessage, AliceintVar)
			dice := ((BobsMessage ^ AliceintVar) % 7)
			fmt.Printf("bob now calculates the dice to :: %d\n", dice)
		} else {

			fmt.Printf("The commitment Alice sent does not match with what she sent.\n")
			fmt.Printf("commitment =          %s\n", AliceComitment)
			fmt.Printf("Bobs generated hash = %s\n", hash)
		}

	}
	//grpc allways need a return so no matter what bob responds with an empty message
	resp := &pb.Void{}
	return resp, nil
}

func (s *BobsDiceServer) SharePublicKey(ctx context.Context, rec *pb.PublicKey) (*pb.PublicKey, error) {
	fmt.Println("**** Meets Alice in a dark alley and shares the public keys ****")
	derBuf, err := x509.MarshalECPrivateKey(BobsPrivateSignKey)
	if err != nil {
		panic(err)
	}
	privCopy, err := x509.ParseECPrivateKey(rec.PublicSignKey)
	if err != nil {
		panic(err)
	}
	AlicePublicSignKey = &privCopy.PublicKey

	resp := &pb.PublicKey{PublicSignKey: derBuf}

	fmt.Println("**** Have exchaged keys with Alice ****")
	return resp, nil

}
