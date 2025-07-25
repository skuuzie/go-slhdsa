package internal

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Algorithm 3 toByte(𝑥, 𝑛)
//
// Converts an integer to a byte string.
func ToByte(x int, n int) []byte {
	S := make([]byte, n)

	total := x

	for i := range n {
		S[n-1-i] = byte(total % 256)
		total >>= 8
	}

	return S
}

// Algorithm 2 toInt(𝑋, 𝑛)
//
// Converts a byte string to an integer
func ToInt(X []byte, n int) int {
	var total int = 0

	for i := range n {
		total = 256*total + int(X[i])
	}
	return total
}

// Byte-array to Big Integer
func ToIntBig(X []byte, n int) *big.Int {
	total := big.NewInt(0)

	for i := range n {
		total = new(big.Int).Mul(total, big.NewInt(256))
		total = new(big.Int).Add(total, big.NewInt(int64(X[i])))
	}
	return total
}

// Big Integer to Byte-array (big-endian)
func ToByteBig(x *big.Int, n int) []byte {
	S := make([]byte, n)

	total := new(big.Int).Set(x)
	mask := big.NewInt(255)

	for i := 0; i < n; i++ {
		lsb := new(big.Int).And(total, mask)
		S[n-1-i] = byte(lsb.Int64())
		total.Rsh(total, 8)
	}

	return S
}

// Ceiling of a/b
func CeilDiv(a, b int64) int64 {
	return (a + b - 1) / b
}

// Algorithm 4 base_2b(𝑋, 𝑏, 𝑜𝑢𝑡_𝑙𝑒𝑛)
//
// Computes the base 2𝑏 representation of 𝑋.
func Base2b(X []byte, b, outLen int) []int {
	var in, bits, total int
	baseb := make([]int, outLen)

	for out := range outLen {
		for bits < b {
			total = (total << 8) + int(X[in])
			in++
			bits += 8
		}
		bits -= b
		baseb[out] = (total >> bits) & ((1 << b) - 1)
	}

	return baseb
}

func Shake128(x []byte, l int) []byte {
	h := sha3.NewSHAKE128()
	h.Write(x)
	result := make([]byte, l)
	h.Read(result)
	return result
}

func Shake256(x []byte, l int) []byte {
	h := sha3.NewSHAKE256()
	h.Write(x)
	result := make([]byte, l)
	h.Read(result)
	return result
}

func Sha1(x []byte) []byte {
	h := sha1.Sum(x)
	return h[:]
}

func Sha256(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}

func Sha224(x []byte) []byte {
	h := sha256.Sum224(x)
	return h[:]
}

func Sha384(x []byte) []byte {
	h := sha512.Sum384(x)
	return h[:]
}

func Sha512_224(x []byte) []byte {
	h := sha512.Sum512_224(x)
	return h[:]
}

func Sha512_256(x []byte) []byte {
	h := sha512.Sum512_256(x)
	return h[:]
}

func Sha512(x []byte) []byte {
	h := sha512.Sum512(x)
	return h[:]
}

func Sha3_224(x []byte) []byte {
	h := sha3.Sum224(x)
	return h[:]
}

func Sha3_256(x []byte) []byte {
	h := sha3.Sum256(x)
	return h[:]
}

func Sha3_384(x []byte) []byte {
	h := sha3.Sum384(x)
	return h[:]
}

func Sha3_512(x []byte) []byte {
	h := sha3.Sum512(x)
	return h[:]
}

func HmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func HmacSha512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Appendix B.2.1 of RFC 8017
func _mgf1(seed []byte, length int, hashFunc func([]byte) []byte) []byte {
	var buf bytes.Buffer
	counter := 0

	for buf.Len() < length {
		data := append(seed, I2OSP(uint32(counter))...)
		buf.Write(hashFunc(data))
		counter++
	}

	return buf.Bytes()[:length]
}

func I2OSP(counter uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, counter)
	return buf
}

func Mgf1Sha256(seed []byte, length int) []byte {
	return _mgf1(seed, length, Sha256)
}

func Mgf1Sha512(seed []byte, length int) []byte {
	return _mgf1(seed, length, Sha512)
}

// Helper for PreHash operation
func PreHash(algorithm PreHashAlgorithm, x, ctx []byte) []byte {
	fmt.Println(algorithm)
	var h []byte
	var id string
	switch algorithm {
	case SHA224:
		h = Sha224(x)
		id = "04"
	case SHA256:
		h = Sha256(x)
		id = "01"
	case SHA384:
		h = Sha384(x)
		id = "02"
	case SHA512:
		h = Sha512(x)
		id = "03"
	case SHA512_224:
		h = Sha512_224(x)
		id = "05"
	case SHA512_256:
		h = Sha512_256(x)
		id = "06"
	case SHA3_224:
		h = Sha3_224(x)
		id = "07"
	case SHA3_256:
		h = Sha3_256(x)
		id = "08"
	case SHA3_384:
		h = Sha3_384(x)
		id = "09"
	case SHA3_512:
		h = Sha3_512(x)
		id = "0a"
	case SHAKE128:
		h = Shake128(x, 32)
		id = "0b"
	case SHAKE256:
		h = Shake256(x, 64)
		id = "0c"
	default:
		panic("unsupported prehash algorithm: " + string(algorithm))
	}

	oid, _ := hex.DecodeString(fmt.Sprintf("06096086480165030402%s", id))
	var buf bytes.Buffer

	buf.Write(ToByte(1, 1))
	buf.Write(ToByte(len(ctx), 1))
	buf.Write(ctx)
	buf.Write(oid)
	buf.Write(h)

	return buf.Bytes()
}

func getRandomBytes(size int) []byte {
	r := make([]byte, size)
	rand.Read(r)
	return r
}
