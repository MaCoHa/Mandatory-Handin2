package main

import (
	enc "Mandatory-Handin2/encryption"
	pb "Mandatory-Handin2/netprotocols"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"google.golang.org/grpc"
)

var AlicePrivateSignKey = new(ecdsa.PrivateKey)
var BobsPublicSignKey = new(ecdsa.PublicKey)

var client pb.DicegameprotocolsClient
var ctx context.Context

var serverPort = "localhost:8085"

var BobsReply = ""

func init() {
	AlicePrivateSignKey = enc.GenPrivateKey()
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
			// TODO: implemente alice comitment and respons potocol
			if !throwDiceWithBob() {
				fmt.Println("???? Something went wrong ????")
			}

		}
	}

}
func sendpublicsignkey() {

	fmt.Println("**** Meets bob in a dark alley and shares public keys ****")
	derBuf, err := x509.MarshalECPrivateKey(AlicePrivateSignKey)
	if err != nil {
		panic(err)
	}
	msg := &pb.PublicKey{PublicSignKey: derBuf}

	resp, err := client.SharePublicKey(ctx, msg)
	if err != nil {
		fmt.Printf("Broadcasting problem: %v", err)
	}

	privCopy, err := x509.ParseECPrivateKey(resp.PublicSignKey)
	if err != nil {
		panic(err)
	}
	BobsPublicSignKey = &privCopy.PublicKey

	fmt.Println("**** Have exchaged keys with Bob ****")

}

func throwDiceWithBob() bool {

	var AliceMessage = strconv.Itoa(rand.Intn(1000))
	fmt.Printf("\n+++++ Alice num %s +++++\n", AliceMessage)

	var random = enc.GetRandom()
	if sendCommitment(AliceMessage, random) {
		fmt.Println("+++ 1 +++")
		if sendMessageAndRandom(AliceMessage, random) {
			fmt.Println("+++ 2 +++")
			intVarBob, err1 := strconv.Atoi(BobsReply)
			intVarAlice, err := strconv.Atoi(AliceMessage)
			if (err == nil) && (err1 == nil) {
				fmt.Println("+++ 3 +++")
				fmt.Printf("Bobs number: %d\nAlice number %d\n", intVarBob, intVarAlice)
				fmt.Printf("Alice calculates the dice throw to %d \n", ((intVarBob ^ intVarAlice) % 7))
				return true
			} else {
				fmt.Println("+++ 4 +++")
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

	fmt.Printf("Alice sign : %t\n", enc.Valid(&AlicePrivateSignKey.PublicKey, string(hash), sign))

	msggrpc := &pb.CommitmentMessage{CommitmentHash: hash, Signature: sign}

	resp, err := client.SendCommitment(ctx, msggrpc)
	if err != nil {
		panic(err)
	}

	if enc.Valid(BobsPublicSignKey, resp.Message, resp.Signature) {
		fmt.Println("**** The signature on Bobs reply machtes his key ****")
		fmt.Println("**** His message have not been modifyed ****")
		BobsReply = resp.Message
		return true
	} else {
		fmt.Println("**** The signature on Bobs reply does not machtes his key ****")
		fmt.Println("**** His message or signature must have been modified ****")
		return false
	}
}

func sendMessageAndRandom(msg string, ran string) bool {

	var sig = enc.Sign(AlicePrivateSignKey, []byte(msg+ran))

	msggrpc := &pb.ControlMessage{Random: ran, Message: msg, Signature: sig}

	_, err := client.SendMessage(ctx, msggrpc)
	if err != nil {
		panic(err)
	}

	return true

}
