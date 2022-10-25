package encryption

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cy "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"math/big"
	mat "math/rand"
	"time"
)

var h = sha256.New()

func RandomInt() int {
	rand, err := rand.Int(rand.Reader, big.NewInt(99999))
	if err != nil {
		panic(err)
	}
	return int(rand.Int64())
}

// this will generate a random string that can be appended to the commitment before the Hash is generated
func GetRandom() string {

	mat.Seed(time.Now().UnixNano())
	//This is the posible characters that the random string will be generated of
	charset := "abcdefghijklmnopqrstuvwxyz123456789!#¤&=£$€"

	var ran string = ""
	// the random string have been limitted to 64 because the RSA could not encrypt larger
	for i := 0; i < 64; i++ {
		ran = ran + string(charset[mat.Intn(len(charset))])
	}

	return ran

}

func GetHash(msg, ran string) []byte {

	io.WriteString(h, msg+ran)
	hash := h.Sum(nil)
	return hash

}

// ************************************************************************************************
// RSA Encryption code taken from https://www.sohamkamani.com/golang/rsa-encryption/
func GenRSAPrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}
func EncryptBytes(msg []byte, publicKey *rsa.PublicKey) []byte {

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		msg,
		nil)
	if err != nil {
		panic(err)
	}
	return encryptedBytes
}
func DcryptBytes(encryptedBytes []byte, privateKey *rsa.PrivateKey) []byte {

	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return decryptedBytes
}

//************************************************************************************************

// generate private signature keys
func GenPrivateSignKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cy.Reader)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func Sign(privateKey *ecdsa.PrivateKey, msg []byte) []byte {

	hash := sha256.Sum256([]byte(msg))

	sig, err := ecdsa.SignASN1(cy.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}

	return sig

}

func Valid(publicKey *ecdsa.PublicKey, msg string, sig []byte) bool {

	hash := sha256.Sum256([]byte(msg))

	valid := ecdsa.VerifyASN1(publicKey, hash[:], []byte(sig))

	return valid
}
