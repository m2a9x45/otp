package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/skip2/go-qrcode"
)

var now = time.Now

// totp := generateHOTP("AKB4TJH2HLQCHAPYVEKUJWGP3H3BZFQK", sha1.New, getCounterTime(), 6)
// fmt.Println(totp)

func GenerateHOTP(key string, alg func() hash.Hash, counter, digits int) string {
	hash := generateHMACSHA1(key, alg, counter)
	fmt.Printf("HMAC-SHA-1 value (hex): %x\n", hash)
	fmt.Printf("hash 10: %x\n", hash[10])
	bytes := generateFourBytes(hash)
	fmt.Printf("fourBytes: %x\n", bytes)
	return computeHTOP(bytes, digits)
}

// Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS
// https://datatracker.ietf.org/doc/html/rfc4226#section-5
func generateHMACSHA1(b32Key string, alg func() hash.Hash, counter int) []byte {
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, uint64(counter))

	key, err := base32.StdEncoding.DecodeString(b32Key)
	if err != nil {
		panic(err)
	}

	mac := hmac.New(alg, key)
	mac.Write(c)
	return mac.Sum(nil)
}

// Step 2: Generate a 4-byte string (Dynamic Truncation)
func generateFourBytes(hash []byte) []byte {
	fmt.Printf("last bit: %x\n", hash[len(hash)-1])
	offsetBit := hash[len(hash)-1] & 0x0F
	fmt.Printf("offsetBit: %x\n", offsetBit)
	offset := int(offsetBit)

	bit := hash[offset] & 0x7f // Mask out / clear most significant bit of the offset
	bit1 := hash[offset+1] & 0xff
	bit2 := hash[offset+2] & 0xff
	bit3 := hash[offset+3] & 0xff

	return []byte{bit, bit1, bit2, bit3}
}

// Step 3: Compute an HOTP value
func computeHTOP(fourBytes []byte, digits int) string {
	num := binary.BigEndian.Uint32(fourBytes)
	fmt.Println("fourBytes (int)", num)

	htop := int(math.Mod(float64(num), math.Pow(10, float64(digits))))

	// Add back the first digit if it's a 0
	htopString := strconv.Itoa(htop)
	if len(htopString) < digits {
		htopString = "0" + htopString
	}
	return htopString
}

// TOTP = HOTP(K, T) where T = (Current Unix time - T0) / X
// https://datatracker.ietf.org/doc/html/rfc6238#section-4
func getCounterTime() int {
	currentTime := now()
	t := currentTime.Unix() / 30
	return int(t)
}

func GenerateKey() string {
	key := make([]byte, 20)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	b32Key := base32.StdEncoding.EncodeToString(key)
	fmt.Println(b32Key)

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/Example:alice@google.com",
	}

	q := u.Query()
	q.Set("secret", b32Key)
	q.Set("issuer", "Example")
	u.RawQuery = q.Encode()

	fmt.Println(u.String())

	err = qrcode.WriteFile(u.String(), qrcode.Medium, 256, "qrcode.png")
	if err != nil {
		panic(err)
	}

	return b32Key
}
