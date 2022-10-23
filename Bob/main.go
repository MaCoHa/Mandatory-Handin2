package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
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
var AliceComitment = []byte{'N', 'E', 'W'}

type BobsDiceServer struct {
	pb.UnimplementedDicegameprotocolsServer
}

func init() {
	BobsPrivateSignKey = enc.GenPrivateSignKey()
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

	AliceComitment = rec.CommitmentHash
	VaildSign := enc.Valid(AlicePublicSignKey, string(rec.CommitmentHash), rec.Signature)
	fmt.Printf("Alice signature vaild ? = %t\n", VaildSign)

	if VaildSign {
		BobsMessage = rand.Intn(10000)
		var sign = enc.Sign(BobsPrivateSignKey, []byte(strconv.Itoa(BobsMessage)))

		resp := &pb.Reply{Message: strconv.Itoa(BobsMessage), Signature: sign}
		return resp, nil
	} else {
		resp := &pb.Reply{Message: "Nope", Signature: []byte{'N', 'O', 'P', 'E'}}
		return resp, errors.New("signature check failed")
	}

}

func (s *BobsDiceServer) SendMessage(ctx context.Context, rec *pb.ControlMessage) (*pb.Void, error) {
	// Check if the message is from Alice
	fmt.Printf("\nAlice signature vaild ? : %t\n", enc.Valid(AlicePublicSignKey, (rec.Message+rec.Random), rec.Signature))

	if enc.Valid(AlicePublicSignKey, (rec.Message + rec.Random), rec.Signature) {
		//message is from Alice and we see if she sent the correct message and random
		var hash = enc.GetHash(rec.Message, rec.Random)

		if bytes.Compare(hash, AliceComitment) == 0 {
			fmt.Printf("Alice sent the same message as was in her commitment\n")
			AliceintVar, err := strconv.Atoi(rec.Message)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Bobs number: %d\nAlice number %d\n", BobsMessage, AliceintVar)
			dice := ((BobsMessage + AliceintVar) % 7)
			fmt.Printf("Bob now calculates the dice to roll :: %d\n", dice)
		} else {

			fmt.Printf("The commitment Alice sent does not match with what she sent.\n")
			fmt.Printf("commitment =          %s\n", AliceComitment)
			fmt.Printf("Bobs generated hash = %s\n", hash)
		}

	}
	//grpc allways needs a return so bob responds with an empty struct
	resp := &pb.Void{}
	return resp, errors.New("Signature Check failed")
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
