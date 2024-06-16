package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hash"
	"testing"
	"time"
)

// https://datatracker.ietf.org/doc/html/rfc4226#page-32
func TestGenerateHMACSHA1(t *testing.T) {
	testCases := []struct {
		counter  int
		expected string
	}{
		{counter: 0, expected: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"},
		{counter: 1, expected: "75a48a19d4cbe100644e8ac1397eea747a2d33ab"},
		{counter: 2, expected: "0bacb7fa082fef30782211938bc1c5e70416ff44"},
		{counter: 3, expected: "66c28227d03a2d5529262ff016a1e6ef76557ece"},
		{counter: 4, expected: "a904c900a64b35909874b33e61c5938a8e15ed1c"},
		{counter: 5, expected: "a37e783d7b7233c083d4f62926c7a25f238d0316"},
		{counter: 6, expected: "bc9cd28561042c83f219324d3c607256c03272ae"},
		{counter: 7, expected: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"},
		{counter: 8, expected: "1b3c89f65e6c9e883012052823443f048b4332db"},
		{counter: 9, expected: "1637409809a679dc698207310c8c7fc07290d9e5"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			// base32 key: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ - > 12345678901234567890
			hash := generateHMACSHA1("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", sha1.New, tc.counter)
			assert.Equal(t, tc.expected, hex.EncodeToString(hash))
		})
	}
}

// https://datatracker.ietf.org/doc/html/rfc4226#section-5.1
func TestGenerateFourBytes(t *testing.T) {
	testCases := []struct {
		hash     string
		expected string
	}{
		{hash: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", expected: "4c93cf18"},
		{hash: "75a48a19d4cbe100644e8ac1397eea747a2d33ab", expected: "41397eea"},
		{hash: "0bacb7fa082fef30782211938bc1c5e70416ff44", expected: "082fef30"},
		{hash: "66c28227d03a2d5529262ff016a1e6ef76557ece", expected: "66ef7655"},
		{hash: "a904c900a64b35909874b33e61c5938a8e15ed1c", expected: "61c5938a"},
		{hash: "a37e783d7b7233c083d4f62926c7a25f238d0316", expected: "33c083d4"},
		{hash: "bc9cd28561042c83f219324d3c607256c03272ae", expected: "7256c032"},
		{hash: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", expected: "04e5b397"},
		{hash: "1b3c89f65e6c9e883012052823443f048b4332db", expected: "2823443f"},
		{hash: "1637409809a679dc698207310c8c7fc07290d9e5", expected: "2679dc69"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			hash, err := hex.DecodeString(tc.hash)
			require.NoError(t, err)
			fourBytes := generateFourBytes(hash)

			expectedBytes, err := hex.DecodeString(tc.expected)
			require.NoError(t, err)

			assert.Equal(t, expectedBytes, fourBytes)
		})
	}
}

// https://datatracker.ietf.org/doc/html/rfc4226#section-5.1
func TestComputeHTOP(t *testing.T) {
	testCases := []struct {
		hash     string
		expected string
	}{
		{hash: "4c93cf18", expected: "755224"},
		{hash: "41397eea", expected: "287082"},
		{hash: "082fef30", expected: "359152"},
		{hash: "66ef7655", expected: "969429"},
		{hash: "61c5938a", expected: "338314"},
		{hash: "33c083d4", expected: "254676"},
		{hash: "7256c032", expected: "287922"},
		{hash: "04e5b397", expected: "162583"},
		{hash: "2823443f", expected: "399871"},
		{hash: "2679dc69", expected: "520489"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			hash, err := hex.DecodeString(tc.hash)
			require.NoError(t, err)
			hotp := computeHTOP(hash, 6)
			assert.Equal(t, tc.expected, hotp)
		})
	}
}

func TestGetCounterTime(t *testing.T) {
	testCases := []struct {
		time        time.Time
		expectedHex string
	}{
		{time: time.Date(1970, 01, 01, 0, 00, 59, 0, time.UTC), expectedHex: "1"},
		{time: time.Date(2005, 03, 18, 1, 58, 29, 0, time.UTC), expectedHex: "23523EC"},
		{time: time.Date(2005, 03, 18, 1, 58, 31, 0, time.UTC), expectedHex: "23523ED"},
		{time: time.Date(2009, 02, 13, 23, 31, 30, 0, time.UTC), expectedHex: "273EF07"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			now = func() time.Time {
				return tc.time
			}
			counter := getCounterTime()
			assert.Equal(t, tc.expectedHex, fmt.Sprintf("%X", counter))
		})
	}
}

// https://datatracker.ietf.org/doc/html/rfc6238
func TestGenerateHOTP(t *testing.T) {
	testCases := []struct {
		time     time.Time
		alg      func() hash.Hash
		algName  string
		expected string
	}{
		{time: time.Date(1970, 01, 01, 00, 00, 59, 0, time.UTC), alg: sha1.New, expected: "94287082"},
		{time: time.Date(1970, 01, 01, 00, 00, 59, 0, time.UTC), alg: sha256.New, algName: "sha256", expected: "46119246"},
		{time: time.Date(1970, 01, 01, 00, 00, 59, 0, time.UTC), alg: sha512.New, algName: "sha512", expected: "90693936"},
		{time: time.Date(2005, 03, 18, 01, 58, 29, 0, time.UTC), alg: sha1.New, expected: "07081804"},
		{time: time.Date(2005, 03, 18, 01, 58, 29, 0, time.UTC), alg: sha256.New, algName: "sha256", expected: "68084774"},
		{time: time.Date(2005, 03, 18, 01, 58, 29, 0, time.UTC), alg: sha512.New, algName: "sha512", expected: "25091201"},
		{time: time.Date(2005, 03, 18, 01, 58, 31, 0, time.UTC), alg: sha1.New, expected: "14050471"},
		{time: time.Date(2005, 03, 18, 01, 58, 31, 0, time.UTC), alg: sha256.New, algName: "sha256", expected: "67062674"},
		{time: time.Date(2005, 03, 18, 01, 58, 31, 0, time.UTC), alg: sha512.New, algName: "sha512", expected: "99943326"},
		{time: time.Date(2009, 02, 13, 23, 31, 30, 0, time.UTC), alg: sha1.New, expected: "89005924"},
		{time: time.Date(2009, 02, 13, 23, 31, 30, 0, time.UTC), alg: sha256.New, algName: "sha256", expected: "91819424"},
		{time: time.Date(2009, 02, 13, 23, 31, 30, 0, time.UTC), alg: sha512.New, algName: "sha512", expected: "93441116"},
		{time: time.Date(2033, 05, 18, 03, 33, 20, 0, time.UTC), alg: sha1.New, expected: "69279037"},
		{time: time.Date(2033, 05, 18, 03, 33, 20, 0, time.UTC), alg: sha256.New, algName: "sha256", expected: "90698825"},
		{time: time.Date(2033, 05, 18, 03, 33, 20, 0, time.UTC), alg: sha512.New, algName: "sha512", expected: "38618901"},
		{time: time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC), alg: sha1.New, expected: "65353130"},
		{time: time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC), alg: sha256.New, algName: "sha256", expected: "77737706"},
		{time: time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC), alg: sha512.New, algName: "sha512", expected: "47863826"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			now = func() time.Time {
				return tc.time
			}

			key := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
			switch tc.algName {
			case "sha256":
				key = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
			case "sha512":
				key = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
			}

			totp := GenerateHOTP(key, tc.alg, getCounterTime(), 8)
			assert.Equal(t, tc.expected, totp)
		})
	}

}
