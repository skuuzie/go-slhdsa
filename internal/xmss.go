package internal

import "math/big"

// Algorithm 9 xmss_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
//
// Computes the root of a Merkle subtree of WOTS+ public keys.
func (ctx *SlhDsa) xmss_node(skSeed []byte, i, z *big.Int, pkSeed []byte, adrs ADRS) []byte {
	var node []byte
	if z.Cmp(big.NewInt(0)) == 0 {
		adrs.SetTypeAndClear(WOTS_HASH)
		adrs.SetKeyPairAddress(i)
		node = ctx.wots_pkGen(skSeed, pkSeed, adrs)
	} else {
		i2 := new(big.Int).Mul(big.NewInt(2), i)
		z1 := new(big.Int).Sub(z, big.NewInt(1))
		lnode := ctx.xmss_node(skSeed, i2, z1, pkSeed, adrs)

		i2plus1 := new(big.Int).Add(i2, big.NewInt(1))
		rnode := ctx.xmss_node(skSeed, i2plus1, z1, pkSeed, adrs)

		adrs.SetTypeAndClear(TREE)
		adrs.SetTreeHeight(z)
		adrs.SetTreeIndex(i)
		node = ctx.hashFunc.H(pkSeed, adrs, append(lnode, rnode...))
	}
	return node
}

// Algorithm 10 xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥, PK.seed, ADRS)
//
// Generates an XMSS signature.
func (ctx *SlhDsa) xmss_sign(m, skSeed []byte, i *big.Int, pkSeed []byte, adrs ADRS) XMSSSignature {

	auth := make([][]byte, ctx.paramSet.Hp)

	for j := range ctx.paramSet.Hp {
		shifted := new(big.Int).Lsh(big.NewInt(1), uint(j))
		divided := new(big.Int).Div(i, shifted)
		k := new(big.Int).Xor(divided, big.NewInt(1))

		jBig := big.NewInt(int64(j))
		auth[j] = ctx.xmss_node(skSeed, k, jBig, pkSeed, adrs)
	}

	adrs.SetTypeAndClear(WOTS_HASH)
	adrs.SetKeyPairAddress(i)

	sig := ctx.wots_sign(m, skSeed, pkSeed, adrs)

	return XMSSSignature{sigWots: sig, authPath: auth}
}

// Algorithm 11 xmss_pkFromSig(𝑖𝑑𝑥, SIG𝑋𝑀𝑆𝑆, 𝑀, PK.seed, ADRS)
//
// Computes an XMSS public key from an XMSS signature
func (ctx *SlhDsa) xmss_pkFromSig(i *big.Int, sigXmss XMSSSignature, m, pkSeed []byte, adrs ADRS) []byte {

	node := make([][]byte, 2)

	adrs.SetTypeAndClear(WOTS_HASH)
	adrs.SetKeyPairAddress(i)

	sig := sigXmss.sigWots
	auth := sigXmss.authPath

	node[0] = ctx.wots_pkFromSig(sig, m, pkSeed, adrs)
	adrs.SetTypeAndClear(TREE)
	adrs.SetTreeIndex(i)

	for k := range ctx.paramSet.Hp {
		kBig := big.NewInt(int64(k))
		adrs.SetTreeHeight(new(big.Int).Add(kBig, big.NewInt(1)))

		shifted := new(big.Int).Lsh(big.NewInt(1), uint(k))
		divided := new(big.Int).Div(i, shifted)
		mod := new(big.Int).Mod(divided, big.NewInt(2))

		if mod.Cmp(big.NewInt(0)) == 0 {
			currentIndex := adrs.GetTreeIndex()
			newIndex := new(big.Int).Div(currentIndex, big.NewInt(2))
			adrs.SetTreeIndex(newIndex)
			node[1] = ctx.hashFunc.H(pkSeed, adrs, append(node[0], auth[k]...))
		} else {
			currentIndex := adrs.GetTreeIndex()
			minusOne := new(big.Int).Sub(currentIndex, big.NewInt(1))
			newIndex := new(big.Int).Div(minusOne, big.NewInt(2))
			adrs.SetTreeIndex(newIndex)
			node[1] = ctx.hashFunc.H(pkSeed, adrs, append(auth[k], node[0]...))
		}
		node[0] = node[1]
	}

	return node[0]
}
