package internal

import (
	"bytes"
	"math/big"
)

// Algorithm 14 fors_skGen(SK.seed, PK.seed, ADRS, 𝑖𝑑𝑥)
//
// Generates a FORS private-key value.
func (ctx *SlhDsa) fors_skGen(skSeed, pkSeed []byte, adrs ADRS, i *big.Int) []byte {
	skAdrs := adrs.Copy()
	skAdrs.SetTypeAndClear(FORS_PRF)
	skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	skAdrs.SetTreeIndex(i)

	return ctx.hashFunc.PRF(pkSeed, skSeed, *skAdrs)
}

// Algorithm 15 fors_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
//
// Computes the root of a Merkle subtree of FORS public values.
func (ctx *SlhDsa) fors_node(skSeed []byte, i, z *big.Int, pkSeed []byte, adrs ADRS) []byte {
	var node []byte

	if z.Cmp(big.NewInt(0)) == 0 {
		sk := ctx.fors_skGen(skSeed, pkSeed, adrs, i)
		adrs.SetTreeHeight(big.NewInt(0))
		adrs.SetTreeIndex(i)
		node = ctx.hashFunc.F(pkSeed, adrs, sk)
	} else {
		i2 := new(big.Int).Mul(big.NewInt(2), i)
		z1 := new(big.Int).Sub(z, big.NewInt(1))
		lnode := ctx.fors_node(skSeed, i2, z1, pkSeed, adrs)

		i2plus1 := new(big.Int).Add(i2, big.NewInt(1))
		rnode := ctx.fors_node(skSeed, i2plus1, z1, pkSeed, adrs)

		adrs.SetTreeHeight(z)
		adrs.SetTreeIndex(i)
		node = ctx.hashFunc.H(pkSeed, adrs, append(lnode, rnode...))
	}

	return node
}

// Algorithm 16 fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
//
// Generates a FORS signature.
func (ctx *SlhDsa) fors_sign(md, skSeed, pkSeed []byte, adrs ADRS) FORSSignature {
	sigFors := FORSSignature{sk: make([][]byte, ctx.paramSet.K), auth: make([][][]byte, ctx.paramSet.K)}

	indices := Base2b(md, ctx.paramSet.A, ctx.paramSet.K)

	for i := range ctx.paramSet.K {
		iBig := big.NewInt(int64(i))
		shifted := new(big.Int).Lsh(big.NewInt(1), uint(ctx.paramSet.A))
		iShifted := new(big.Int).Mul(iBig, shifted)
		indexBig := big.NewInt(int64(indices[i]))
		skIndex := new(big.Int).Add(iShifted, indexBig)
		sigFors.sk[i] = ctx.fors_skGen(skSeed, pkSeed, adrs, skIndex)

		sigFors.auth[i] = make([][]byte, ctx.paramSet.A)
		for j := range ctx.paramSet.A {
			jShifted := new(big.Int).Lsh(big.NewInt(1), uint(j))
			divided := new(big.Int).Div(indexBig, jShifted)
			s := new(big.Int).Xor(divided, big.NewInt(1))

			ajShifted := new(big.Int).Lsh(big.NewInt(1), uint(ctx.paramSet.A-j))
			iAjShifted := new(big.Int).Mul(iBig, ajShifted)
			nodeIndex := new(big.Int).Add(iAjShifted, s)
			jBig := big.NewInt(int64(j))
			sigFors.auth[i][j] = ctx.fors_node(skSeed, nodeIndex, jBig, pkSeed, adrs)
		}
	}

	return sigFors
}

// Algorithm 17 fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
//
// Computes a FORS public key from a FORS signature
func (ctx *SlhDsa) fors_pkFromSig(sigFors FORSSignature, md, pkSeed []byte, adrs ADRS) []byte {
	root := make([][]byte, ctx.paramSet.K)
	node := make([][]byte, 2)
	indices := Base2b(md, ctx.paramSet.A, ctx.paramSet.K)

	for i := range ctx.paramSet.K {
		sk := sigFors.sk[i]
		adrs.SetTreeHeight(big.NewInt(0))

		iBig := big.NewInt(int64(i))
		shifted := new(big.Int).Lsh(big.NewInt(1), uint(ctx.paramSet.A))
		iShifted := new(big.Int).Mul(iBig, shifted)
		indexBig := big.NewInt(int64(indices[i]))
		treeIndex := new(big.Int).Add(iShifted, indexBig)
		adrs.SetTreeIndex(treeIndex)

		node[0] = ctx.hashFunc.F(pkSeed, adrs, sk)
		auth := sigFors.auth[i]

		for j := range ctx.paramSet.A {
			jBig := big.NewInt(int64(j))
			adrs.SetTreeHeight(new(big.Int).Add(jBig, big.NewInt(1)))

			jShifted := new(big.Int).Lsh(big.NewInt(1), uint(j))
			divided := new(big.Int).Div(indexBig, jShifted)
			mod := new(big.Int).Mod(divided, big.NewInt(2))

			if mod.Cmp(big.NewInt(0)) == 0 {
				currentIndex := adrs.GetTreeIndex()
				newIndex := new(big.Int).Div(currentIndex, big.NewInt(2))
				adrs.SetTreeIndex(newIndex)
				node[1] = ctx.hashFunc.H(pkSeed, adrs, append(node[0], auth[j]...))
			} else {
				currentIndex := adrs.GetTreeIndex()
				minusOne := new(big.Int).Sub(currentIndex, big.NewInt(1))
				newIndex := new(big.Int).Div(minusOne, big.NewInt(2))
				adrs.SetTreeIndex(newIndex)
				node[1] = ctx.hashFunc.H(pkSeed, adrs, append(auth[j], node[0]...))
			}
			node[0] = node[1]
		}
		root[i] = node[0]
	}
	forsPkAdrs := adrs.Copy()
	forsPkAdrs.SetTypeAndClear(FORS_ROOTS)
	forsPkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	return ctx.hashFunc.T_l(pkSeed, *forsPkAdrs, bytes.Join(root, []byte("")))
}

// Helper to deserialize FORS Signature
func (s *FORSSignature) Combine() []byte {
	var buffer bytes.Buffer

	for i := range s.sk {
		buffer.Write(s.sk[i])
		combinedAuthPart := bytes.Join(s.auth[i], []byte(""))
		buffer.Write(combinedAuthPart)
	}

	return buffer.Bytes()
}
