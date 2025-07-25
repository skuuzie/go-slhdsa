package internal

import (
	"bytes"
)

func (s *SHA2) H_msg(r, pkSeed, pkRoot, m []byte) []byte {

	// Lv 1   : MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	// Lv 3/5 : MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)

	buf := bytes.NewBuffer(r)
	buf.Write(pkSeed)
	buf.Write(pkRoot)
	buf.Write(m)

	buf1 := bytes.NewBuffer(r)
	buf1.Write(pkSeed)
	buf1.Write(s.hash(buf.Bytes()))

	return s.mgf(buf1.Bytes(), s.paramSet.M)
}

func (s *SHA2) PRF(pkSeed, skSeed []byte, adrs ADRS) []byte {

	// Lv 1   : Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	// Lv 3/5 : Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))

	buf := bytes.NewBuffer(pkSeed)
	buf.Write(ToByte(0, 64-s.paramSet.N))
	buf.Write(adrs.GetCompressedADRS())
	buf.Write(skSeed)

	return Sha256(buf.Bytes())[:s.paramSet.N]
}

func (s *SHA2) PRF_msg(skPRF, optRand, m []byte) []byte {

	// Lv 1   : Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	// Lv 3/5 : Trunc𝑛(HMAC-SHA-512(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))

	return s.hmac(skPRF, append(optRand, m...))[:s.paramSet.N]
}

func (s *SHA2) F(pkSeed []byte, adrs ADRS, m_1 []byte) []byte {

	// Lv 1   : Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// Lv 3/5 : Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))

	buf := bytes.NewBuffer(pkSeed)
	buf.Write(ToByte(0, 64-s.paramSet.N))
	buf.Write(adrs.GetCompressedADRS())
	buf.Write(m_1)

	return Sha256(buf.Bytes())[:s.paramSet.N]
}

func (s *SHA2) H(pkSeed []byte, adrs ADRS, m_2 []byte) []byte {

	// Lv 1   : Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	// Lv 3/5 : Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))

	var b int

	if s.paramSet.N == 16 {
		b = 64
	} else if s.paramSet.N == 24 || s.paramSet.N == 32 {
		b = 128
	}

	buf := bytes.NewBuffer(pkSeed)
	buf.Write(ToByte(0, b-s.paramSet.N))
	buf.Write(adrs.GetCompressedADRS())
	buf.Write(m_2)

	return s.hash(buf.Bytes())[:s.paramSet.N]
}

func (s *SHA2) T_l(pkSeed []byte, adrs ADRS, m_l []byte) []byte {

	// Lv 1   : Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	// Lv 3/5 : Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))

	var b int

	if s.paramSet.N == 16 {
		b = 64
	} else if s.paramSet.N == 24 || s.paramSet.N == 32 {
		b = 128
	}

	buf := bytes.NewBuffer(pkSeed)
	buf.Write(ToByte(0, b-s.paramSet.N))
	buf.Write(adrs.GetCompressedADRS())
	buf.Write(m_l)

	return s.hash(buf.Bytes())[:s.paramSet.N]
}
