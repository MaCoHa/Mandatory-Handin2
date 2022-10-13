package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"google.golang.org/grpc"
)

const (
	port = "localhost:8085"
)

type Commitment struct {
	commitmentHash string
	signature      []byte
}
type Reply struct {
	message   string
	signature []byte
}
type Control struct {
	random    string
	message   string
	signature []byte
}

var BobsPrivateSignKey *ecdsa.PrivateKey
var AlicePublicSignKey *ecdsa.PublicKey

var commitment Commitment
var reply Reply
var control Control
var BobsMessage int

type BobsDiceServer struct {
	pb.UnimplementedDicegameprotocolsServer
}

func init() {
	BobsPrivateSignKey = enc.GenPrivateKey()
}

func main() {

	lis, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Printf("failed to listen: %v\n", err)
	}
	s := grpc.NewServer()
	pb.RegisterDicegameprotocolsServer(s, &BobsDiceServer{})
	fmt.Printf("server listening at %v\n", lis.Addr())
	if err := s.Serve(lis); err != nil {
		fmt.Printf("failed to serve: %v\n", err)
	}

}

func (s *BobsDiceServer) SendCommitment(ctx context.Context, rec *pb.CommitmentMessage) (*pb.Reply, error) {
	err := json.Unmarshal([]byte(rec.CipherMessage), commitment)
	if err != nil {
		panic(err)
	}
	// Check if the message is from Alice
	if enc.Valid(AlicePublicSignKey, commitment.commitmentHash, commitment.signature) {
		var BobsMessage = rand.Intn(100)
		var sign = enc.Sign(BobsPrivateSignKey, strconv.Itoa(BobsMessage))
		reply.signature = sign
		reply.message = strconv.Itoa(BobsMessage)

		json, err := json.Marshal(reply)
		if err != nil {
			panic(err)
		}
		resp := &pb.Reply{CipherMessage: json}
		return resp, nil
	} else {
		resp := &pb.Reply{CipherMessage: nil}
		return resp, nil
	}

}

func (s *BobsDiceServer) SendMessage(ctx context.Context, rec *pb.ControlMessage) (*pb.Void, error) {

	err := json.Unmarshal([]byte(rec.CipherMessage), control)
	if err != nil {
		panic(err)
	}
	// Check if the message is from Alice
	if enc.Valid(AlicePublicSignKey, control.message, control.signature) {
		//message is from Alice and we see if she sent the correct message and random
		var hash = enc.GetHash(control.message, control.random)

		fmt.Printf("with the message :: %s and with random %s\n", control.message, control.random)
		fmt.Printf("Bob generates a hash that is :: %s\n", hash)

		if hash == commitment.commitmentHash {
			fmt.Printf("Alice sent the same message as was in here commitment\n")
			intVar, _ := strconv.Atoi(control.message)
			dice := (BobsMessage * intVar % 6)
			fmt.Printf("bob now calculates the dice to :: %d\n", dice)
		} else {
			fmt.Printf("The commitment Alice sent does not match with what she sent.\n")
			fmt.Printf("commitment =          %s\n", commitment.commitmentHash)
			fmt.Printf("Bobs generated hash = %s\n", hash)
		}
	}
	//grpc allways need a return so no matter what bob responds with an empty message
	resp := &pb.Void{}
	return resp, nil
}

func (s *BobsDiceServer) SharePublicKey(ctx context.Context, rec *pb.PublicKey) (*pb.PublicKey, error) {

	derBuf, _ := x509.MarshalECPrivateKey(BobsPrivateSignKey)

	privCopy, _ := x509.ParseECPrivateKey(rec.PublicSignKey)

	AlicePublicSignKey = &privCopy.PublicKey

	resp := &pb.PublicKey{PublicSignKey: derBuf}

	return resp, nil

}
