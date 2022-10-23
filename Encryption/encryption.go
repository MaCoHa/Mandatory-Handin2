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
	mat "math/rand"
	"time"
)

var alicePublicKey = "ubc6&ipxwâ1jwstqrb#s&ibâ#Â92zÂp5$o7u&âqyÂ&h3aÂk1#a9Â#agnqrvfgd#cz2z£11g$g#¬vr¬rqkovy=9mrdÂhgÂxÂo3¬q¬1obg&£oe4=tsvw1cuÂlr5821$oemxÂm4=diaÂÂckcps¤f£â#aÂw&3l¤ÂbÂ6¤ujf¤y2ÂbÂknug#5ae#7u468c71nÂ&¬Âvcaâa2zwca7zh6kmz441zk##ÂÂ9xvetÂ¬4&9q$¬a#kn¤$vmbcqn97c7wy191i!9t18"
var bobPublicKey = "&¤w!f!e#h#g3xccr£2Âhu¤ncuaw#4lc8bkb££6â=rr¬a1gl¬¤p6pd2cj26uz48ct68!gcm&Âc£st4&Ânyp6l4z5jrzs!aqp2ÂeeÂi98j¤ui9a8af¤g&zv#=$#r4l$#eh5¤pb4stknbjj¬apav7v7#571¤9qg=kv3!ei9qahl=3qxu¬i=zwohqt735dy4rncu1ÂÂd1ÂÂwl£6c=5ujgyfd&uijÂfxbj6¤nudpd!Âf!7g¬iâfpq6s5=£y99mÂÂoiwl5&d"
var h = sha256.New()

func GetRandom() string {

	mat.Seed(time.Now().UnixNano())

	// String
	charset := "abcdefghijklmnopqrstuvwxyz123456789!#¤&=£$€"

	var ran string = ""

	for i := 0; i < 265; i++ {
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
func encryptBytes(msg []byte, publicKey *rsa.PublicKey) []byte {

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
func dcryptBytes(encryptedBytes []byte, privateKey *rsa.PrivateKey) []byte {

	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return decryptedBytes
}

//************************************************************************************************

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
