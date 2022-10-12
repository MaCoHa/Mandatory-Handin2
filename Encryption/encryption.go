package encryption

import (
	"crypto/sha256"
	"io"
	"math/rand"
	"time"
)

func getRandom() string {

	rand.Seed(time.Now().UnixNano())

	// String
	charset := "abcdefghijklmnopqrstuvwxyz123456789!#¤%&/()=@£$€{[]}|"

	var ran string = ""

	for i := 0; i < 265; i++ {
		ran = ran + string(charset[rand.Intn(len(charset))])
	}

	return ran

}

func getHash(msg, ran string) string {

	h := sha256.New()
	io.WriteString(h, msg+ran)
	hash := string(h.Sum(nil))
	return hash

}
