package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
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
var BobsPrivateEncKey = new(rsa.PrivateKey)
var AlicePublicSignKey = new(ecdsa.PublicKey)
var AlicePublicEncKey = new(rsa.PublicKey)

var BobsMessage int
var AliceComitment = []byte{'N', 'E', 'W'}

type BobsDiceServer struct {
	pb.UnimplementedDicegameprotocolsServer
}

func init() {
	BobsPrivateSignKey = enc.GenPrivateSignKey()
	BobsPrivateEncKey = enc.GenRSAPrivateKey()
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

	AliceComitment = enc.DcryptBytes(rec.CommitmentHash, BobsPrivateEncKey)
	decSign := enc.DcryptBytes(rec.Signature, BobsPrivateEncKey)
	VaildSign := enc.Valid(AlicePublicSignKey, string(AliceComitment), decSign)
	fmt.Printf("Alice signature vaild ? = %t\n", VaildSign)

	if VaildSign {
		BobsMessage = rand.Intn(10000)
		sign := enc.Sign(BobsPrivateSignKey, []byte(strconv.Itoa(BobsMessage)))
		encSign := enc.EncryptBytes(sign, AlicePublicEncKey)
		fmt.Printf("\n%x\n", encSign)
		encMsg := enc.EncryptBytes([]byte(strconv.Itoa(BobsMessage)), AlicePublicEncKey)
		fmt.Printf("\n%x\n", encMsg)
		resp := &pb.Reply{Message: encMsg, Signature: encSign}
		return resp, nil
	} else {
		resp := &pb.Reply{Message: []byte{'N', 'O', 'P', 'E'}, Signature: []byte{'N', 'O', 'P', 'E'}}
		return resp, errors.New("signature check failed")
	}

}

func (s *BobsDiceServer) SendMessage(ctx context.Context, rec *pb.ControlMessage) (*pb.Void, error) {
	// Check if the message is from Alice
	decRan := string(enc.DcryptBytes(rec.Random, BobsPrivateEncKey))
	decMsg := string(enc.DcryptBytes(rec.Message, BobsPrivateEncKey))
	decSign := enc.DcryptBytes(rec.Signature, BobsPrivateEncKey)
	aliceValid := enc.Valid(AlicePublicSignKey, (decMsg + decRan), decSign)
	fmt.Printf("\nAlice signature vaild ? : %t\n", aliceValid)

	if aliceValid {
		//message is from Alice and we see if she sent the correct message and random
		var hash = enc.GetHash(decMsg, decRan)

		if bytes.Compare(hash, AliceComitment) == 0 {
			fmt.Printf("Alice sent the same message as was in her commitment\n")
			AliceintVar, err := strconv.Atoi(decMsg)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Bobs number: %d\nAlice number %d\n", BobsMessage, AliceintVar)
			dice := ((BobsMessage + AliceintVar) % 7)
			fmt.Printf("Bob now calculates the dice to roll :: %d\n", dice)
			resp := &pb.Void{}
			return resp, nil
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
	//Formats the sign key so it can be sent
	byteSignKey, err := x509.MarshalECPrivateKey(BobsPrivateSignKey)
	if err != nil {
		panic(err)
	}
	pubEncKey, err := json.Marshal(&BobsPrivateEncKey.PublicKey)
	if err != nil {
		panic(err)
	}

	privCopy, err := x509.ParseECPrivateKey(rec.PublicSignKey)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(rec.PublicEncKey, AlicePublicEncKey)
	if err != nil {
		panic(err)
	}
	AlicePublicSignKey = &privCopy.PublicKey

	resp := &pb.PublicKey{PublicSignKey: byteSignKey, PublicEncKey: pubEncKey}

	fmt.Println("**** Have exchaged keys with Alice ****")
	return resp, nil

}
