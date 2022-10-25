package encryption

import (
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

type Commitment struct {
	CommitmentHash []byte `json:"commitmenthash"`
	Signature      []byte `json:"signature"`
}

type Reply struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

type ControlMessage struct {
	Random    []byte `json:"random"`
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

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
	h.Reset()
	return hash

}

func GenRSAPrivateKey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}
func EncryptLargeBytes(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {

	msgLen := len(msg)
	step := publicKey.Size() - 2*h.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(h, rand.Reader, publicKey, msg[start:finish], nil)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}
	return encryptedBytes, nil
}
func DcryptLargeBytes(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error) {

	msgLen := len(msg)
	step := privateKey.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(h, rand.Reader, privateKey, msg[start:finish], nil)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil

}

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
