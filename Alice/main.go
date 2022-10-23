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
	"math/rand"
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

func init() {
	AlicePrivateSignKey = enc.GenPrivateSignKey()
	AlicePrivateEncKey = enc.GenRSAPrivateKey()
}
func main() {

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
	// Converts the sent keys from bob
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

	var AliceMessage = strconv.Itoa(rand.Intn(1000))
	var random = enc.GetRandom()
	// Send initial commitment to bob
	if sendCommitment(AliceMessage, random) {
		// Send meg, ran to bob so he can check
		if sendMessageAndRandom(AliceMessage, random) {

			intVarBob, err1 := strconv.Atoi(BobsReply)
			intVarAlice, err := strconv.Atoi(AliceMessage)
			if (err == nil) && (err1 == nil) {
				fmt.Printf("Bobs number: %d\nAlice number %d\n", intVarBob, intVarAlice)
				fmt.Printf("Alice calculates the dice throw to roll :: %d \n", ((intVarBob + intVarAlice) % 7))
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
	encHash := enc.EncryptBytes(hash, BobsPublicEncKey)
	encSigh := enc.EncryptBytes(sign, BobsPublicEncKey)

	msggrpc := &pb.CommitmentMessage{CommitmentHash: encHash, Signature: encSigh}

	resp, err := client.SendCommitment(ctx, msggrpc)
	if err != nil {
		panic(err)
	}
	// decrypt Bobs responds
	decMsg := string(enc.DcryptBytes(resp.Message, AlicePrivateEncKey))
	decSign := enc.DcryptBytes(resp.Signature, AlicePrivateEncKey)

	if enc.Valid(BobsPublicSignKey, decMsg, decSign) {
		fmt.Println("**** The signature on Bobs reply machtes his key ****")
		fmt.Println("**** His message have not been modifyed ****")
		BobsReply = decMsg
		return true
	} else {
		fmt.Println("**** The signature on Bobs reply does not machtes his key ****")
		fmt.Println("**** His message or signature must have been modified ****")
		return false
	}
}

func sendMessageAndRandom(msg string, ran string) bool {

	var sign = enc.Sign(AlicePrivateSignKey, []byte(msg+ran))
	//Encrypt the messages being sent to Bob
	encSign := enc.EncryptBytes(sign, BobsPublicEncKey)
	encMsg := enc.EncryptBytes([]byte(msg), BobsPublicEncKey)
	encRan := enc.EncryptBytes([]byte(ran), BobsPublicEncKey)

	msggrpc := &pb.ControlMessage{Random: encRan, Message: encMsg, Signature: encSign}

	_, err := client.SendMessage(ctx, msggrpc)
	if err != nil {
		panic(err)
	}

	return true

}
