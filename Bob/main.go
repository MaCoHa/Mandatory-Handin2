package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
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
	port = ":6060"
)

var BobsPrivateSignKey *ecdsa.PrivateKey
var AlicePublicSignKey *ecdsa.PublicKey

var commitment string
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

func (s *BobsDiceServer) SendCommitment(ctx context.Context, rec *pb.HashMessage) (*pb.Reply, error) {
	commitment = rec.Commitment
	var BobsMessage = rand.Intn(100)

	resp := &pb.Reply{Message: strconv.Itoa(BobsMessage)}
	return resp, nil
}

func (s *BobsDiceServer) SendMessage(ctx context.Context, rec *pb.ControlMessage) (*pb.Void, error) {

	var hash = enc.GetHash(rec.Message, rec.Random)
	fmt.Printf("with the message :: %s and with random %s\n", rec.Message, rec.Random)
	fmt.Printf("Bob generates a hash that is :: %s\n", hash)

	if hash == commitment {
		fmt.Printf("Alice sent the same message as was in here commitment\n")
		intVar, _ := strconv.Atoi(rec.Message)
		dice := (BobsMessage * intVar % 6)
		fmt.Printf("bob now calculates the dice to :: %d\n", dice)
	} else {
		fmt.Printf("The commitment Alice sent does not match with what she sent.\n")
		fmt.Printf("commitment =          %s\n", commitment)
		fmt.Printf("Bobs generated hash = %s\n", hash)
	}

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
