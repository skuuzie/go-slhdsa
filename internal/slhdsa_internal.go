package internal

import (
	"bytes"
	"errors"
	"math/big"
)

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA key pair.
func (ctx *SlhDsa) SlhKeygenInternal(skSeed, skPrf, pkSeed []byte) (PrivateKey, PublicKey) {
	adrs := ADRS{bytes: ToByte(0, 32)}
	adrs.SetLayerAddress(big.NewInt(int64(ctx.paramSet.D - 1)))
	pkRoot := ctx.xmss_node(skSeed, big.NewInt(0), big.NewInt(int64(ctx.paramSet.Hp)), pkSeed, adrs)

	pk := PublicKey{
		KeyBytes: append(pkSeed, pkRoot...),
		pkSeed:   pkSeed,
		pkRoot:   pkRoot,
	}

	skBuf := bytes.NewBuffer(skSeed)

	skBuf.Write(skPrf)
	skBuf.Write(pkSeed)
	skBuf.Write(pkRoot)

	sk := PrivateKey{
		KeyBytes: skBuf.Bytes(),
		skSeed:   skSeed,
		skPrf:    skPrf,
		pkSeed:   pkSeed,
		pkRoot:   pkRoot,
	}

	return sk, pk
}

// Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
//
// Generates an SLH-DSA signature.
func (ctx *SlhDsa) SlhSignInternal(m []byte, sk PrivateKey, addrnd []byte) SLHDSASignature {
	var optRand []byte

	adrs := ADRS{bytes: ToByte(0, 32)}

	if len(addrnd) == 0 {
		optRand = sk.pkSeed
	} else {
		optRand = addrnd
	}

	r := ctx.hashFunc.PRF_msg(sk.skPrf, optRand, m)
	digest := ctx.hashFunc.H_msg(r, sk.pkSeed, sk.pkRoot, m)
	md, idxTree, idxLeaf := ctx.getMdTreeIndexes(digest)
	adrs.SetTreeAddress(idxTree)
	adrs.SetTypeAndClear(FORS_TREE)
	adrs.SetKeyPairAddress(idxLeaf)
	sigFORS := ctx.fors_sign(md, sk.skSeed, sk.pkSeed, adrs)
	pkFORS := ctx.fors_pkFromSig(sigFORS, md, sk.pkSeed, adrs)
	sigHT := ctx.ht_sign(pkFORS, sk.skSeed, sk.pkSeed, idxTree, idxLeaf)

	return SLHDSASignature{R: r, sigFORS: sigFORS, sigHT: sigHT}
}

// Algorithm 20 slh_verify_internal(𝑀, SIG, PK)
//
// Verifies an SLH-DSA signature
func (ctx *SlhDsa) SlhVerifyInternal(m []byte, sig SLHDSASignature, pk PublicKey) bool {
	adrs := ADRS{bytes: ToByte(0, 32)}

	r := sig.R
	sigFORS := sig.sigFORS
	sigHT := sig.sigHT

	digest := ctx.hashFunc.H_msg(r, pk.pkSeed, pk.pkRoot, m)
	md, idxTree, idxLeaf := ctx.getMdTreeIndexes(digest)

	adrs.SetTreeAddress(idxTree)
	adrs.SetTypeAndClear(FORS_TREE)
	adrs.SetKeyPairAddress(idxLeaf)

	pkFORS := ctx.fors_pkFromSig(sigFORS, md, pk.pkSeed, adrs)

	return ctx.ht_verify(pkFORS, sigHT, pk.pkSeed, idxTree, idxLeaf, pk.pkRoot)
}

// Helper for:
//
// Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
//
// Algorithm 20 slh_verify_internal(𝑀, SIG, PK)
func (ctx *SlhDsa) getMdTreeIndexes(digest []byte) ([]byte, *big.Int, *big.Int) {
	k := big.NewInt(int64(ctx.paramSet.K))
	a := big.NewInt(int64(ctx.paramSet.A))
	d := big.NewInt(int64(ctx.paramSet.D))
	h := big.NewInt(int64(ctx.paramSet.H))

	digBuf := bytes.NewReader(digest)

	ka1 := CeilDiv(k.Int64()*a.Int64(), 8)
	md := make([]byte, ka1)

	hd := h.Int64() / d.Int64()
	hhd := h.Int64() - hd

	tmpIdxTree := make([]byte, CeilDiv(hhd, 8))
	tmpIdxLeaf := make([]byte, CeilDiv(hd, 8))

	digBuf.Read(md)
	digBuf.Read(tmpIdxTree)
	digBuf.Read(tmpIdxLeaf)

	idxTreeBig := ToIntBig(tmpIdxTree, int(CeilDiv(hhd, 8)))
	modTree := new(big.Int).Lsh(big.NewInt(1), uint(hhd))
	idxTree := new(big.Int).Mod(idxTreeBig, modTree)

	idxLeafBig := ToIntBig(tmpIdxLeaf, int(CeilDiv(hd, 8)))
	modLeaf := new(big.Int).Lsh(big.NewInt(1), uint(hd))
	idxLeaf := new(big.Int).Mod(idxLeafBig, modLeaf)

	return md, idxTree, idxLeaf
}

// Convert SLH-DSA signature to raw bytes
func (s *SLHDSASignature) Deserialize(context SlhDsa) ([]byte, error) {
	rLen := context.paramSet.N
	sigFORSLen := (context.paramSet.K * (1 + context.paramSet.A)) * context.paramSet.N
	sigHTLen := (context.paramSet.H + context.paramSet.D*context.wotsParam.len) * context.paramSet.N
	sigLen := rLen + sigFORSLen + sigHTLen

	var sig bytes.Buffer

	// Randomizer
	sig.Write(s.R)

	// Deserialize FORS Signature
	for i := range context.paramSet.K {
		sig.Write(s.sigFORS.sk[i])
		for j := range context.paramSet.A {
			sig.Write(s.sigFORS.auth[i][j])
		}
	}

	// Deserialize Hypertree Signature
	for i := range context.paramSet.D {
		sig.Write(bytes.Join(s.sigHT.sigXmss[i].sigWots.sigOts, []byte("")))
		sig.Write(bytes.Join(s.sigHT.sigXmss[i].authPath, []byte("")))
	}

	if sig.Len() != sigLen {
		panic("[Debug] signature deserialization failure - check implementation")
	}

	return sig.Bytes(), nil
}

// Convert raw bytes to structured SLH-DSA signature
func SerializeToSig(context SlhDsa, signature []byte) (SLHDSASignature, error) {
	var s SLHDSASignature

	rLen := context.paramSet.N
	sigFORSLen := (context.paramSet.K * (1 + context.paramSet.A)) * context.paramSet.N
	sigHTLen := (context.paramSet.H + context.paramSet.D*context.wotsParam.len) * context.paramSet.N
	sigLen := rLen + sigFORSLen + sigHTLen

	if len(signature) != sigLen {
		return s, errors.New("invalid signature")
	}

	sig := bytes.NewReader(signature)

	// Randomizer
	s.R = make([]byte, rLen)
	sig.Read(s.R)

	// FORS Signature
	s.sigFORS.sk = make([][]byte, context.paramSet.K)
	s.sigFORS.auth = make([][][]byte, context.paramSet.K)

	for i := range context.paramSet.K {
		s.sigFORS.sk[i] = make([]byte, context.paramSet.N)
		sig.Read(s.sigFORS.sk[i])

		s.sigFORS.auth[i] = make([][]byte, context.paramSet.A)
		for j := range context.paramSet.A {
			s.sigFORS.auth[i][j] = make([]byte, context.paramSet.N)
			sig.Read(s.sigFORS.auth[i][j])
		}
	}

	// Hypertree Signature
	s.sigHT.sigXmss = make([]XMSSSignature, context.paramSet.D)

	for i := range context.paramSet.D {
		s.sigHT.sigXmss[i].sigWots.sigOts = make([][]byte, context.wotsParam.len)
		for j := range context.wotsParam.len {
			s.sigHT.sigXmss[i].sigWots.sigOts[j] = make([]byte, context.paramSet.N)
			sig.Read(s.sigHT.sigXmss[i].sigWots.sigOts[j])
		}

		s.sigHT.sigXmss[i].authPath = make([][]byte, context.paramSet.Hp)
		for j := range context.paramSet.Hp {
			s.sigHT.sigXmss[i].authPath[j] = make([]byte, context.paramSet.N)
			sig.Read(s.sigHT.sigXmss[i].authPath[j])
		}
	}

	ds, _ := s.Deserialize(context)
	if !bytes.Equal(ds, signature) {
		panic("[Debug] signature serialization failure - check implementation")
	}

	return s, nil
}
