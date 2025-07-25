package slhdsa

import (
	"errors"
	"reflect"

	slhdsa "github.com/skuuzie/go-slhdsa/internal"
)

// Available SLH-DSA parameter sets
var ParameterSet = slhdsa.ParameterSets{
	SLHDSA_SHA2_128s:  "SLH-DSA-SHA2-128s",
	SLHDSA_SHAKE_128s: "SLH-DSA-SHAKE-128s",
	SLHDSA_SHA2_128f:  "SLH-DSA-SHA2-128f",
	SLHDSA_SHAKE_128f: "SLH-DSA-SHAKE-128f",
	SLHDSA_SHA2_192s:  "SLH-DSA-SHA2-192s",
	SLHDSA_SHAKE_192s: "SLH-DSA-SHAKE-192s",
	SLHDSA_SHA2_192f:  "SLH-DSA-SHA2-192f",
	SLHDSA_SHAKE_192f: "SLH-DSA-SHAKE-192f",
	SLHDSA_SHA2_256s:  "SLH-DSA-SHA2-256s",
	SLHDSA_SHAKE_256s: "SLH-DSA-SHAKE-256s",
	SLHDSA_SHA2_256f:  "SLH-DSA-SHA2-256f",
	SLHDSA_SHAKE_256f: "SLH-DSA-SHAKE-256f",
}

// Available SLH-DSA Pre-Hashing algorithms
var PreHashAlgorithm = slhdsa.PreHashAlgorithms{
	Pure:       "Pure",
	SHA224:     "SHA2-224",
	SHA256:     "SHA2-256",
	SHA384:     "SHA2-384",
	SHA512:     "SHA2-512",
	SHA512_224: "SHA2-512/224",
	SHA512_256: "SHA2-512/256",
	SHA3_224:   "SHA3-224",
	SHA3_256:   "SHA3-256",
	SHA3_384:   "SHA3-384",
	SHA3_512:   "SHA3-512",
	SHAKE128:   "SHAKE-128",
	SHAKE256:   "SHAKE-256",
}

type iSLHDSA interface {
	// Generate crypto-secure random SLH-DSA Private and Public key
	//
	// Use `.KeyBytes()` to get byte-array of the key
	GenerateKeyPair() (slhdsa.PrivateKey, slhdsa.PublicKey, error)

	// Generate SLH-DSA signature
	//
	// Mandatory: `sk`, `message`, `useAdditionalRandomness`
	//
	// Optional (may be nil): `context`, `prehash`
	GenerateSignature(sk slhdsa.PrivateKey, message, context []byte, useAdditionalRandomness bool, prehash string) ([]byte, error)

	// Verify SLH-DSA signature
	//
	// Mandatory: `pk`, `message`
	//
	// Optional (may be nil): `context`, `prehash`
	VerifySignature(pk slhdsa.PublicKey, message, signature, context []byte, prehash string) (bool, error)

	// Convert raw bytes of SLH-DSA public key to structured
	GetPublicKeyFromBytes(pk []byte) (slhdsa.PublicKey, error)

	// Convert raw bytes of SLH-DSA private key to structured
	GetPrivateKeyFromBytes(sk []byte) (slhdsa.PrivateKey, error)
}

// Validate parameter set
func validate(paramSet string) bool {
	val := reflect.ValueOf(ParameterSet)

	for i := range val.NumField() {
		fieldValue := val.Field(i).String()
		if fieldValue == paramSet {
			return true
		}
	}

	return false
}

// Create new instance of SLH-DSA
func New(paramSet string) (iSLHDSA, error) {
	if !validate(paramSet) {
		return nil, errors.New("invalid SLH-DSA parameter set")
	}

	return slhdsa.NewSlhDsa(paramSet)
}
