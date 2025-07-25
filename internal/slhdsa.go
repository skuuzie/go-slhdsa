package internal

import (
	"bytes"
	"errors"
	"math/bits"
)

func (ctx *SlhDsa) GenerateKeyPair() (PrivateKey, PublicKey, error) {
	skSeed := getRandomBytes(ctx.paramSet.N)
	skPrf := getRandomBytes(ctx.paramSet.N)
	pkSeed := getRandomBytes(ctx.paramSet.N)

	sk, pk := ctx.SlhKeygenInternal(skSeed, skPrf, pkSeed)

	return sk, pk, nil
}

func (ctx *SlhDsa) GenerateSignature(sk PrivateKey, message, context []byte, useAdditionalRandomness bool, preHashAlg string) ([]byte, error) {
	var mp []byte
	var randomness []byte

	if context != nil {
		if len(context) > 255 {
			return nil, errors.New("context string cannot exceed length of 255")
		}
	}

	alg := PreHashAlgorithmMap[preHashAlg]
	if alg != Pure {
		mp = PreHash(alg, message, context)
	} else {
		mp = append(append(ToByte(0, 1), append(ToByte(len(context), 1), context...)...), message...)
	}

	if useAdditionalRandomness {
		randomness = getRandomBytes(ctx.paramSet.N)
	}

	sig := ctx.SlhSignInternal(mp, sk, randomness)
	deserialized, err := sig.Deserialize(*ctx)

	if err != nil {
		panic(err)
	}

	return deserialized, nil
}

func (ctx *SlhDsa) VerifySignature(pk PublicKey, message, signature, context []byte, preHashAlg string) (bool, error) {
	var mp []byte

	if context != nil {
		if len(context) > 255 {
			return false, errors.New("context string cannot exceed length of 255")
		}
	}

	alg := PreHashAlgorithmMap[preHashAlg]
	if alg != Pure {
		mp = PreHash(alg, message, context)
	} else {
		mp = append(append(ToByte(0, 1), append(ToByte(len(context), 1), context...)...), message...)
	}

	sig, err := SerializeToSig(*ctx, signature)

	if err != nil {
		return false, err
	}

	return ctx.SlhVerifyInternal(mp, sig, pk), nil
}

func (ctx *SlhDsa) GetPrivateKeyFromBytes(sk []byte) (PrivateKey, error) {
	if len(sk) != ctx.paramSet.N*4 {
		return PrivateKey{}, errors.New("invalid private key")
	}

	_sk := PrivateKey{
		KeyBytes: sk,
		skSeed:   make([]byte, ctx.paramSet.N),
		skPrf:    make([]byte, ctx.paramSet.N),
		pkSeed:   make([]byte, ctx.paramSet.N),
		pkRoot:   make([]byte, ctx.paramSet.N),
	}

	buf := bytes.NewReader(sk)
	buf.Read(_sk.skSeed)
	buf.Read(_sk.skPrf)
	buf.Read(_sk.pkSeed)
	buf.Read(_sk.pkRoot)

	return _sk, nil
}

func (ctx *SlhDsa) GetPublicKeyFromBytes(pk []byte) (PublicKey, error) {
	if len(pk) != ctx.paramSet.N*2 {
		return PublicKey{}, errors.New("invalid public key")
	}

	_pk := PublicKey{
		KeyBytes: pk,
		pkSeed:   make([]byte, ctx.paramSet.N),
		pkRoot:   make([]byte, ctx.paramSet.N),
	}

	buf := bytes.NewReader(pk)
	buf.Read(_pk.pkSeed)
	buf.Read(_pk.pkRoot)

	return _pk, nil
}

func NewSlhDsa(parameterSet string) (*SlhDsa, error) {
	var _p = SLHDSAParamMap[parameterSet]

	w := 1 << _p.LgW
	len1 := (8 * _p.N) / _p.LgW
	len2 := bits.Len(uint(len1*(w-1)))/_p.LgW + 1
	len := len1 + len2

	wotsParam := WOTSParam{
		w:    w,
		len1: len1,
		len2: len2,
		len:  len,
	}

	switch _p.HashName {
	case "SHAKE":
		h := SHAKE{paramSet: &_p}

		return &SlhDsa{algName: parameterSet, paramSet: &_p, hashFunc: &h, wotsParam: &wotsParam}, nil

	case "SHA2":
		h := SHA2{paramSet: &_p}

		switch _p.N {
		case 16:
			h.hash = Sha256
			h.mgf = Mgf1Sha256
			h.hmac = HmacSha256
		case 24, 32:
			h.hash = Sha512
			h.mgf = Mgf1Sha512
			h.hmac = HmacSha512
		default:
			break
		}

		return &SlhDsa{algName: parameterSet, paramSet: &_p, hashFunc: &h, wotsParam: &wotsParam}, nil
	}

	return nil, errors.New("invalid parameter set")
}
