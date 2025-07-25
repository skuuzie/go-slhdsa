package internal

import (
	"bytes"
)

func (s *SHAKE) H_msg(r, pkSeed, pkRoot, m []byte) []byte {

	// SHAKE256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀, 8𝑚)

	buf := bytes.NewBuffer(r)

	buf.Write(pkSeed)
	buf.Write(pkRoot)
	buf.Write(m)

	return Shake256(buf.Bytes(), s.paramSet.M)
}

func (s *SHAKE) PRF(pkSeed, skSeed []byte, adrs ADRS) []byte {

	// SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)

	buf := bytes.NewBuffer(pkSeed)

	buf.Write(adrs.bytes)
	buf.Write(skSeed)

	return Shake256(buf.Bytes(), s.paramSet.N)
}

func (s *SHAKE) PRF_msg(skPRF, optRand, m []byte) []byte {

	// SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)

	buf := bytes.NewBuffer(skPRF)

	buf.Write(optRand)
	buf.Write(m)

	return Shake256(buf.Bytes(), s.paramSet.N)
}

func (s *SHAKE) F(pkSeed []byte, adrs ADRS, m_1 []byte) []byte {

	// SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)

	buf := bytes.NewBuffer(pkSeed)

	buf.Write(adrs.bytes)
	buf.Write(m_1)

	return Shake256(buf.Bytes(), s.paramSet.N)
}

func (s *SHAKE) H(pkSeed []byte, adrs ADRS, m_2 []byte) []byte {

	// SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)

	buf := bytes.NewBuffer(pkSeed)

	buf.Write(adrs.bytes)
	buf.Write(m_2)

	return Shake256(buf.Bytes(), s.paramSet.N)
}

func (s *SHAKE) T_l(pkSeed []byte, adrs ADRS, m_l []byte) []byte {

	// SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)

	buf := bytes.NewBuffer(pkSeed)

	buf.Write(adrs.bytes)
	buf.Write(m_l)

	return Shake256(buf.Bytes(), s.paramSet.N)
}
