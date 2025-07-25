package internal

import (
	"bytes"
	"math/big"
)

// Algorithm 12 ht_sign(𝑀, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
//
// Generates a hypertree signature.
func (ctx *SlhDsa) ht_sign(m, skSeed, pkSeed []byte, idxTree, idxLeaf *big.Int) HypertreeSignature {
	var sigHT HypertreeSignature

	sigHT.sigXmss = make([]XMSSSignature, ctx.paramSet.D)

	adrs := ADRS{bytes: ToByte(0, 32)}
	adrs.SetTreeAddress(idxTree)
	sigTmp := ctx.xmss_sign(m, skSeed, idxLeaf, pkSeed, adrs)
	sigHT.sigXmss[0] = sigTmp
	root := ctx.xmss_pkFromSig(idxLeaf, sigTmp, m, pkSeed, adrs)

	for j := 1; j < ctx.paramSet.D; j++ {
		shifted := new(big.Int).Lsh(big.NewInt(1), uint(ctx.paramSet.Hp))
		idxLeaf = new(big.Int).Mod(idxTree, shifted)
		idxTree = new(big.Int).Rsh(idxTree, uint(ctx.paramSet.Hp))
		jBig := big.NewInt(int64(j))
		adrs.SetLayerAddress(jBig)
		adrs.SetTreeAddress(idxTree)
		sigTmp = ctx.xmss_sign(root, skSeed, idxLeaf, pkSeed, adrs)
		sigHT.sigXmss[j] = sigTmp
		if j < ctx.paramSet.D {
			root = ctx.xmss_pkFromSig(idxLeaf, sigTmp, root, pkSeed, adrs)
		}
	}

	return sigHT
}

// Algorithm 13 ht_verify(𝑀, SIG𝐻𝑇, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.root)
//
// Verifies a hypertree signature.
func (ctx *SlhDsa) ht_verify(m []byte, sigHT HypertreeSignature, pkSeed []byte, idxTree, idxLeaf *big.Int, pkRoot []byte) bool {
	adrs := ADRS{bytes: ToByte(0, 32)}
	adrs.SetTreeAddress(idxTree)
	sigTmp := sigHT.sigXmss[0]
	node := ctx.xmss_pkFromSig(idxLeaf, sigTmp, m, pkSeed, adrs)

	for j := 1; j < ctx.paramSet.D; j++ {
		shifted := new(big.Int).Lsh(big.NewInt(1), uint(ctx.paramSet.Hp))
		idxLeaf = new(big.Int).Mod(idxTree, shifted)
		idxTree = new(big.Int).Rsh(idxTree, uint(ctx.paramSet.Hp))
		jBig := big.NewInt(int64(j))
		adrs.SetLayerAddress(jBig)
		adrs.SetTreeAddress(idxTree)
		sigTmp = sigHT.sigXmss[j]
		node = ctx.xmss_pkFromSig(idxLeaf, sigTmp, node, pkSeed, adrs)
	}

	return bytes.Equal(node, pkRoot)
}
