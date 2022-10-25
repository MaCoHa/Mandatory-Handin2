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
	"net"
	"strconv"

	"google.golang.org/grpc"
)

var commitment *enc.Commitment
var message *enc.ControlMessage
var reply *enc.Reply

const (
	port = "localhost:8085"
)

var BobsPrivateSignKey = new(ecdsa.PrivateKey)
var BobsPrivateEncKey = new(rsa.PrivateKey)
var AlicePublicSignKey = new(ecdsa.PublicKey)
var AlicePublicEncKey = new(rsa.PublicKey)

var BobsMessage int
var AliceCommitment = []byte{'N', 'E', 'W'}

type BobsDiceServer struct {
	pb.UnimplementedDicegameprotocolsServer
}

func init() {
	BobsPrivateSignKey = enc.GenPrivateSignKey()
	BobsPrivateEncKey = enc.GenRSAPrivateKey()

	commitment = &enc.Commitment{}
	message = &enc.ControlMessage{}
	reply = &enc.Reply{}
}

func main() {
	//grpc setting up the server
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
	jsonmsg, err := enc.DcryptLargeBytes(rec.Ciphertext, BobsPrivateEncKey)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(jsonmsg, commitment)
	if err != nil {
		panic(err)
	}
	AliceCommitment = commitment.CommitmentHash
	//Checks if the signature machtes alices signature
	VaildSign := enc.Valid(AlicePublicSignKey, string(AliceCommitment), commitment.Signature)
	fmt.Printf("\n************ New dice throw ***************\n")
	fmt.Printf("Recivede Commitment from alice\n")
	fmt.Printf("Alice signature vaild ? = %t\n", VaildSign)

	if VaildSign {
		//The signature was vaild now respond to bob
		BobsMessage = enc.RandomInt()
		sign := enc.Sign(BobsPrivateSignKey, []byte(strconv.Itoa(BobsMessage)))
		reply.Message = []byte(strconv.Itoa(BobsMessage))
		reply.Signature = sign
		jsonmsg, err := json.Marshal(reply)
		if err != nil {
			panic(err)
		}
		encmsg, err := enc.EncryptLargeBytes(jsonmsg, AlicePublicEncKey)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Sent number to Alice\n")
		resp := &pb.Reply{Ciphertext: encmsg}
		return resp, nil
	} else {
		//The signature was not vaild now respond with an termination message allowing alice to know something was compromised
		resp := &pb.Reply{Ciphertext: []byte{'N', 'O', 'P', 'E'}}
		return resp, errors.New("signature check failed")
	}

}

func (s *BobsDiceServer) SendMessage(ctx context.Context, rec *pb.ControlMessage) (*pb.Void, error) {
	jsonmsg, err := enc.DcryptLargeBytes(rec.Ciphertext, BobsPrivateEncKey)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(jsonmsg, message)
	if err != nil {
		panic(err)
	}

	// Check if the signature form alice is vaild
	aliceValid := enc.Valid(AlicePublicSignKey, (string(message.Message) + string(message.Random)), message.Signature)
	fmt.Printf("Recivede Random and Alice's number from Alice\n")
	fmt.Printf("Alice signature vaild ? = %t\n", aliceValid)

	if aliceValid {
		//message is from Alice and we see if she sent the correct message and random
		var hash = enc.GetHash(string(message.Message), string(message.Random))

		if bytes.Compare(hash, AliceCommitment) == 0 {
			fmt.Printf("Alice sent the same message as was in her commitment\n")
			AliceintVar, err := strconv.Atoi(string(message.Message))
			if err != nil {
				panic(err)
			}
			fmt.Printf("Bobs number: %d\nAlice number %d\n", BobsMessage, AliceintVar)
			dice := ((BobsMessage + AliceintVar) % 6) + 1
			fmt.Printf("Bob now calculates the dice to roll :: %d\n\n", dice)
			resp := &pb.Void{}
			return resp, nil
		} else {

			fmt.Printf("The commitment Alice sent does not match with what she sent.\n")
			fmt.Printf("commitment =          %s\n", AliceCommitment)
			fmt.Printf("Bobs generated hash = %s\n", hash)
		}

	}
	//grpc allways needs a return so bob responds with an empty struct
	resp := &pb.Void{}
	return resp, errors.New("signature check failed")
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

	// converts the keys sendt from Alice
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
