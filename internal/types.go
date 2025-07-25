package internal

// Core SLH-DSA Structure
type SlhDsa struct {
	algName   string
	paramSet  *SLHDSAParams
	hashFunc  HashFunctions
	wotsParam *WOTSParam
}

// User Interface Bridging
type ParameterSets struct {
	SLHDSA_SHA2_128s  string
	SLHDSA_SHAKE_128s string
	SLHDSA_SHA2_128f  string
	SLHDSA_SHAKE_128f string
	SLHDSA_SHA2_192s  string
	SLHDSA_SHAKE_192s string
	SLHDSA_SHA2_192f  string
	SLHDSA_SHAKE_192f string
	SLHDSA_SHA2_256s  string
	SLHDSA_SHAKE_256s string
	SLHDSA_SHA2_256f  string
	SLHDSA_SHAKE_256f string
}

// User Interface Bridging
type PreHashAlgorithms struct {
	Pure       string
	SHA224     string
	SHA256     string
	SHA384     string
	SHA512     string
	SHA512_224 string
	SHA512_256 string
	SHA3_224   string
	SHA3_256   string
	SHA3_384   string
	SHA3_512   string
	SHAKE128   string
	SHAKE256   string
}

// Internal or Testing Use
type PreHashAlgorithm string

// SLH-DSA Parameter Set structure
type SLHDSAParams struct {
	HashName string
	N        int
	H        int
	D        int
	Hp       int
	A        int
	K        int
	LgW      int
	M        int
}

// SLH-DSA Public Key
type PublicKey struct {
	KeyBytes []byte
	pkSeed   []byte
	pkRoot   []byte
}

// SLH-DSA Private/Secret Key
type PrivateKey struct {
	KeyBytes []byte
	skSeed   []byte
	skPrf    []byte
	pkSeed   []byte
	pkRoot   []byte
}

// 4.1 Hash Functions and Pseudorandom Functions
type HashFunctions interface {
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚)
	H_msg(r, pkSeed, pkRoot, m []byte) []byte

	// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛)
	PRF(pkSeed, skSeed []byte, adrs ADRS) []byte

	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛)
	PRF_msg(skPRF, optRand, m []byte) []byte

	// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛)
	F(pkSeed []byte, adrs ADRS, m_1 []byte) []byte

	// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛)
	H(pkSeed []byte, adrs ADRS, m_2 []byte) []byte

	// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛)
	T_l(pkSeed []byte, adrs ADRS, m_l []byte) []byte
}

// SLH-DSA with SHAKE
type SHAKE struct {
	paramSet *SLHDSAParams
}

// SLH-DSA with SHA-2
type SHA2 struct {
	paramSet *SLHDSAParams
	hash     func([]byte) []byte
	mgf      func([]byte, int) []byte
	hmac     func([]byte, []byte) []byte
}

// Winternitz One-Time Signature Parameters
type WOTSParam struct {
	w    int
	len  int
	len1 int
	len2 int
}

// Winternitz One-Time Signature
type WOTSSignature struct {
	sigOts [][]byte
}

// eXtended Merkle Signature Scheme (XMSS)
type XMSSSignature struct {
	sigWots  WOTSSignature
	authPath [][]byte
}

// SLH-DSA Hypertree Signature
type HypertreeSignature struct {
	sigXmss []XMSSSignature
}

// Forest of Random Subsets (FORS)
type FORSSignature struct {
	sk   [][]byte
	auth [][][]byte
}

// Core SLH-DSA Signature
type SLHDSASignature struct {
	R       []byte
	sigFORS FORSSignature
	sigHT   HypertreeSignature
}

// Intenal Parameter Sets definition
var SLHDSAParamMap = map[string]SLHDSAParams{
	"SLH-DSA-SHA2-128s": {
		HashName: "SHA2",
		N:        16,
		H:        63,
		D:        7,
		Hp:       9,
		A:        12,
		K:        14,
		LgW:      4,
		M:        30,
	},
	"SLH-DSA-SHAKE-128s": {
		HashName: "SHAKE",
		N:        16,
		H:        63,
		D:        7,
		Hp:       9,
		A:        12,
		K:        14,
		LgW:      4,
		M:        30,
	},
	"SLH-DSA-SHA2-128f": {
		HashName: "SHA2",
		N:        16,
		H:        66,
		D:        22,
		Hp:       3,
		A:        6,
		K:        33,
		LgW:      4,
		M:        34,
	},
	"SLH-DSA-SHAKE-128f": {
		HashName: "SHAKE",
		N:        16,
		H:        66,
		D:        22,
		Hp:       3,
		A:        6,
		K:        33,
		LgW:      4,
		M:        34,
	},
	"SLH-DSA-SHA2-192s": {
		HashName: "SHA2",
		N:        24,
		H:        63,
		D:        7,
		Hp:       9,
		A:        14,
		K:        17,
		LgW:      4,
		M:        39,
	},
	"SLH-DSA-SHAKE-192s": {
		HashName: "SHAKE",
		N:        24,
		H:        63,
		D:        7,
		Hp:       9,
		A:        14,
		K:        17,
		LgW:      4,
		M:        39,
	},
	"SLH-DSA-SHA2-192f": {
		HashName: "SHA2",
		N:        24,
		H:        66,
		D:        22,
		Hp:       3,
		A:        8,
		K:        33,
		LgW:      4,
		M:        42,
	},
	"SLH-DSA-SHAKE-192f": {
		HashName: "SHAKE",
		N:        24,
		H:        66,
		D:        22,
		Hp:       3,
		A:        8,
		K:        33,
		LgW:      4,
		M:        42,
	},
	"SLH-DSA-SHA2-256s": {
		HashName: "SHA2",
		N:        32,
		H:        64,
		D:        8,
		Hp:       8,
		A:        14,
		K:        22,
		LgW:      4,
		M:        47,
	},
	"SLH-DSA-SHAKE-256s": {
		HashName: "SHAKE",
		N:        32,
		H:        64,
		D:        8,
		Hp:       8,
		A:        14,
		K:        22,
		LgW:      4,
		M:        47,
	},
	"SLH-DSA-SHA2-256f": {
		HashName: "SHA2",
		N:        32,
		H:        68,
		D:        17,
		Hp:       4,
		A:        9,
		K:        35,
		LgW:      4,
		M:        49,
	},
	"SLH-DSA-SHAKE-256f": {
		HashName: "SHAKE",
		N:        32,
		H:        68,
		D:        17,
		Hp:       4,
		A:        9,
		K:        35,
		LgW:      4,
		M:        49,
	},
}

// Internal or Testing Use
const (
	Pure       PreHashAlgorithm = "Pure"
	SHA224     PreHashAlgorithm = "SHA2-224"
	SHA256     PreHashAlgorithm = "SHA2-256"
	SHA384     PreHashAlgorithm = "SHA2-384"
	SHA512     PreHashAlgorithm = "SHA2-512"
	SHA512_224 PreHashAlgorithm = "SHA2-512/224"
	SHA512_256 PreHashAlgorithm = "SHA2-512/256"
	SHA3_224   PreHashAlgorithm = "SHA3-224"
	SHA3_256   PreHashAlgorithm = "SHA3-256"
	SHA3_384   PreHashAlgorithm = "SHA3-384"
	SHA3_512   PreHashAlgorithm = "SHA3-512"
	SHAKE128   PreHashAlgorithm = "SHAKE-128"
	SHAKE256   PreHashAlgorithm = "SHAKE-256"
)

// Internal or Testing Use
var PreHashAlgorithmMap = map[string]PreHashAlgorithm{
	"Pure":         Pure,
	"SHA2-224":     SHA224,
	"SHA2-256":     SHA256,
	"SHA2-384":     SHA384,
	"SHA2-512":     SHA512,
	"SHA2-512/224": SHA512_224,
	"SHA2-512/256": SHA512_256,
	"SHA3-224":     SHA3_224,
	"SHA3-256":     SHA3_256,
	"SHA3-384":     SHA3_384,
	"SHA3-512":     SHA3_512,
	"SHAKE-128":    SHAKE128,
	"SHAKE-256":    SHAKE256,
}
