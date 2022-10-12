package encryption

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cy "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	mat "math/rand"
	"time"
)

func GetRandom() string {

	mat.Seed(time.Now().UnixNano())

	// String
	charset := "abcdefghijklmnopqrstuvwxyzåæø123456789!#¤%&/()=@£$€{[]}|"

	var ran string = ""

	for i := 0; i < 265; i++ {
		ran = ran + string(charset[mat.Intn(len(charset))])
	}

	return ran

}

func GetHash(msg, ran string) string {

	h := sha256.New()
	io.WriteString(h, msg+ran)
	hash := string(h.Sum(nil))
	return hash

}

// taken from https://www.developer.com/languages/cryptography-in-go/
// uses a aes encryption libary (golangs crypto)
func EncryptMessage(key string, message string) string {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
	}
	msgByte := make([]byte, len(message))
	c.Encrypt(msgByte, []byte(message))
	return hex.EncodeToString(msgByte)
}

// taken from https://www.developer.com/languages/cryptography-in-go/
// uses a aes encryption libary (golangs crypto)
func DecryptMessage(key string, ciphertext string) string {
	txt, _ := hex.DecodeString(ciphertext)
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
	}
	msgByte := make([]byte, len(txt))
	c.Decrypt(msgByte, []byte(txt))

	msg := string(msgByte[:])
	return msg
}

func GenPrivateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cy.Reader)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func Sign(privateKey *ecdsa.PrivateKey, msg string) []byte {

	hash := sha256.Sum256([]byte(msg))

	sig, err := ecdsa.SignASN1(cy.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}

	return sig

}

func Valid(publicKey *ecdsa.PublicKey, msg string, sig []byte) bool {

	hash := sha256.Sum256([]byte(msg))
	valid := ecdsa.VerifyASN1(publicKey, hash[:], sig)

	return valid
}
