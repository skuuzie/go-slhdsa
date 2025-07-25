package internal

import (
	"bytes"
	"math/big"
)

// Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//
// Chaining function used in WOTS+.
func (ctx *SlhDsa) chain(X []byte, i, s int, pkSeed []byte, adrs ADRS) []byte {
	tmp := X

	for j := i; j < i+s; j++ {
		adrs.SetHashAddress(big.NewInt(int64(j)))
		tmp = ctx.hashFunc.F(pkSeed, adrs, tmp)
	}

	return tmp
}

// Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)
//
// Generates a WOTS+ public key.
func (ctx *SlhDsa) wots_pkGen(skSeed, pkSeed []byte, adrs ADRS) []byte {
	skAdrs := adrs.Copy()

	skAdrs.SetTypeAndClear(WOTS_PRF)
	skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	tmp := bytes.NewBuffer(make([]byte, 0))

	for i := range ctx.wotsParam.len {
		skAdrs.SetChainAddress(big.NewInt(int64(i)))
		sk := ctx.hashFunc.PRF(pkSeed, skSeed, *skAdrs)
		adrs.SetChainAddress(big.NewInt(int64(i)))
		tmp.Write(ctx.chain(sk, 0, ctx.wotsParam.w-1, pkSeed, adrs))
	}

	wotsPkAdrs := adrs.Copy()
	wotsPkAdrs.SetTypeAndClear(WOTS_PK)
	wotsPkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	return ctx.hashFunc.T_l(pkSeed, *wotsPkAdrs, tmp.Bytes())
}

// Algorithm 7 wots_sign(𝑀, SK.seed, PK.seed, ADRS)
//
// Generates a WOTS+ signature on an 𝑛-byte message.
func (ctx *SlhDsa) wots_sign(m, skSeed, pkSeed []byte, adrs ADRS) WOTSSignature {
	sig := WOTSSignature{sigOts: make([][]byte, ctx.wotsParam.len)}

	csum := 0
	msg := Base2b(m, ctx.paramSet.LgW, ctx.wotsParam.len1)

	for i := range ctx.wotsParam.len1 {
		csum = csum + ctx.wotsParam.w - 1 - msg[i]
	}

	csum = csum << ((8 - ((ctx.wotsParam.len2 * ctx.paramSet.LgW) % 8)) % 8)

	msg = append(msg, Base2b(ToByte(csum, ((ctx.wotsParam.len2*ctx.paramSet.LgW)+7)/8), ctx.paramSet.LgW, ctx.wotsParam.len2)...)

	skAdrs := adrs.Copy()
	skAdrs.SetTypeAndClear(WOTS_PRF)
	skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	for i := range ctx.wotsParam.len {
		skAdrs.SetChainAddress(big.NewInt(int64(i)))
		sk := ctx.hashFunc.PRF(pkSeed, skSeed, *skAdrs)
		adrs.SetChainAddress(big.NewInt(int64(i)))
		sig.sigOts[i] = ctx.chain(sk, 0, msg[i], pkSeed, adrs)
	}

	return sig
}

// Algorithm 8 wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
//
// Computes a WOTS+ public key from a message and its signature.
func (ctx *SlhDsa) wots_pkFromSig(sig WOTSSignature, m, pkSeed []byte, adrs ADRS) []byte {
	csum := 0
	msg := Base2b(m, ctx.paramSet.LgW, ctx.wotsParam.len1)

	for i := range ctx.wotsParam.len1 {
		csum = csum + ctx.wotsParam.w - 1 - msg[i]
	}

	if ctx.paramSet.LgW == 4 {
		csum <<= 4
	} else {
		csum = csum << ((8 - ((ctx.wotsParam.len2 * ctx.paramSet.LgW) % 8)) % 8)
	}

	msg = append(msg, Base2b(ToByte(csum, ((ctx.wotsParam.len2*ctx.paramSet.LgW)+7)/8), ctx.paramSet.LgW, ctx.wotsParam.len2)...)

	tmp := make([][]byte, ctx.wotsParam.len)

	for i := range ctx.wotsParam.len {
		adrs.SetChainAddress(big.NewInt(int64(i)))
		tmp[i] = ctx.chain(
			sig.sigOts[i],
			msg[i],
			ctx.wotsParam.w-1-msg[i],
			pkSeed,
			adrs)
	}

	wotsPkAdrs := adrs.Copy()
	wotsPkAdrs.SetTypeAndClear(WOTS_PK)
	wotsPkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	return ctx.hashFunc.T_l(pkSeed, *wotsPkAdrs, bytes.Join(tmp, []byte("")))
}
