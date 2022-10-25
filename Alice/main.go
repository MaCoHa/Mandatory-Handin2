package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc"
)

var AlicePrivateSignKey = new(ecdsa.PrivateKey)
var AlicePrivateEncKey = new(rsa.PrivateKey)
var BobsPublicSignKey = new(ecdsa.PublicKey)
var BobsPublicEncKey = new(rsa.PublicKey)

var client pb.DicegameprotocolsClient
var ctx context.Context

var serverPort = "localhost:8085"

var BobsReply = ""

var commitment *enc.Commitment
var message *enc.ControlMessage
var reply *enc.Reply

func init() {
	AlicePrivateSignKey = enc.GenPrivateSignKey()
	AlicePrivateEncKey = enc.GenRSAPrivateKey()

	commitment = &enc.Commitment{}
	message = &enc.ControlMessage{}
	reply = &enc.Reply{}

}
func main() {
	//grpc connectiong to the server / Bob
	conn, err := grpc.Dial(serverPort, grpc.WithInsecure())
	if err != nil {
		fmt.Print(err.Error())
		panic(err)
	}
	defer func(conn *grpc.ClientConn) {
		err := conn.Close()
		if err != nil {
			fmt.Print(err.Error())
			panic(err)

		}
	}(conn)

	client = pb.NewDicegameprotocolsClient(conn)

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sendpublicsignkey() // exchages public keys with Bob
	for {
		input := ""
		fmt.Printf("\n************ New dice throw ***************\n")
		fmt.Println("write anything to throw dice with Bob:")
		fmt.Scan(&input)
		if input != "" {

			if !throwDiceWithBob() {
				fmt.Println("???? Something went wrong ????")
			}

		}
	}

}

func sendpublicsignkey() {
	// This is not surpose to happen over the network and is therefore not encrypted
	fmt.Println("**** Meets bob in a dark alley and shares public keys ****")
	// Converts Alices keys to a sendable format
	byteSignKey, err := x509.MarshalECPrivateKey(AlicePrivateSignKey)
	if err != nil {
		panic(err)
	}
	pubEncKey, err := json.Marshal(&AlicePrivateEncKey.PublicKey)
	if err != nil {
		panic(err)
	}

	msg := &pb.PublicKey{PublicSignKey: byteSignKey, PublicEncKey: pubEncKey}

	resp, err := client.SharePublicKey(ctx, msg)
	if err != nil {
		fmt.Printf("Broadcasting problem: %v", err)
	}
	// Converts the keys recived from bob
	privCopy, err := x509.ParseECPrivateKey(resp.PublicSignKey)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(resp.PublicEncKey, BobsPublicEncKey)
	if err != nil {
		panic(err)
	}
	BobsPublicSignKey = &privCopy.PublicKey

	fmt.Println("**** Have exchaged keys with Bob ****")

}

func throwDiceWithBob() bool {

	var AliceMessage = strconv.Itoa(enc.RandomInt())
	var random = enc.GetRandom()
	// Send initial commitment to bob
	if sendCommitment(AliceMessage, random) {
		// Send msg and ran to bob so he can check
		if sendMessageAndRandom(AliceMessage, random) {

			intVarBob, err1 := strconv.Atoi(BobsReply)
			intVarAlice, err := strconv.Atoi(AliceMessage)
			if (err == nil) && (err1 == nil) {
				fmt.Printf("Bobs number: %d\nAlice number %d\n", intVarBob, intVarAlice)
				fmt.Printf("Alice calculates the dice throw to roll :: %d \n", (((intVarBob + intVarAlice) % 6) + 1))
				return true
			} else {
				fmt.Printf("???? One of the string -> int failede \n")
				fmt.Printf("???? Bob %e \n", err1)
				fmt.Printf("???? Alice %e \n", err)
			}

		}
	}

	return false

}

func sendCommitment(msg string, ran string) bool {

	hash := enc.GetHash(msg, ran)
	sign := enc.Sign(AlicePrivateSignKey, hash)
	// encrypt the information being sent to bob
	commitment.CommitmentHash = hash
	commitment.Signature = sign
	msgjson, err := json.Marshal(commitment)
	if err != nil {
		panic(err)
	}
	encmsg, err := enc.EncryptLargeBytes(msgjson, BobsPublicEncKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Sent Commitment to Bob\n")
	msggrpc := &pb.CommitmentMessage{Ciphertext: encmsg}

	resp, err := client.SendCommitment(ctx, msggrpc)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Recived number from Bob\n")

	respjson, err := enc.DcryptLargeBytes(resp.Ciphertext, AlicePrivateEncKey)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(respjson, reply)
	if err != nil {
		panic(err)
	}
	// decrypt Bobs responds

	if enc.Valid(BobsPublicSignKey, string(reply.Message), reply.Signature) {
		fmt.Printf("Bobs signature vaild ? = %t\n", true)
		BobsReply = string(reply.Message)
		return true
	} else {
		fmt.Printf("Bobs signature vaild ? = %t\n", false)
		return false
	}
}

func sendMessageAndRandom(msg string, ran string) bool {
	//sends the message and random so bob can compute the hash
	fmt.Printf("Sent random and number to Bob\n")
	//creates a signature from the combination of the message and random
	var sign = enc.Sign(AlicePrivateSignKey, []byte(msg+ran))
	//Encrypt the messages being sent to Bob
	message.Message = []byte(msg)
	message.Random = []byte(ran)
	message.Signature = sign
	msgjson, err := json.Marshal(message)
	if err != nil {
		panic(err)
	}
	encmsg, err := enc.EncryptLargeBytes(msgjson, BobsPublicEncKey)
	msggrpc := &pb.ControlMessage{Ciphertext: encmsg}

	_, err = client.SendMessage(ctx, msggrpc)
	if err != nil {
		panic(err)
	}

	return true

}
