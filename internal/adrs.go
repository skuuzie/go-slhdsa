package internal

import (
	"math/big"
)

// 4.2 Addresses
type ADRS struct {
	bytes []byte
}

type ADRSType int64

const (
	WOTS_HASH  ADRSType = 0
	WOTS_PK    ADRSType = 1
	TREE       ADRSType = 2
	FORS_TREE  ADRSType = 3
	FORS_ROOTS ADRSType = 4
	WOTS_PRF   ADRSType = 5
	FORS_PRF   ADRSType = 6
)

func (a *ADRS) SetLayerAddress(l *big.Int) {
	copy(a.bytes[0:4], ToByteBig(l, 4))
}

func (a *ADRS) SetTreeAddress(t *big.Int) {
	copy(a.bytes[4:16], ToByteBig(t, 12))
}

func (a *ADRS) SetTypeAndClear(Y ADRSType) {
	copy(a.bytes[16:20], ToByte(int(Y), 4))
	copy(a.bytes[20:32], ToByte(0, 12))
}

func (a *ADRS) SetKeyPairAddress(i *big.Int) {
	copy(a.bytes[20:24], ToByteBig(i, 4))
}

func (a *ADRS) SetChainAddress(i *big.Int) {
	copy(a.bytes[24:28], ToByteBig(i, 4))
}

func (a *ADRS) SetTreeHeight(i *big.Int) {
	a.SetChainAddress(i)
}

func (a *ADRS) SetHashAddress(i *big.Int) {
	copy(a.bytes[28:32], ToByteBig(i, 4))
}

func (a *ADRS) SetTreeIndex(i *big.Int) {
	a.SetHashAddress(i)
}

func (a *ADRS) GetKeyPairAddress() *big.Int {
	return big.NewInt(0).SetBytes(a.bytes[20:24])
}

func (a *ADRS) GetTreeIndex() *big.Int {
	return big.NewInt(0).SetBytes(a.bytes[28:32])
}

func (a *ADRS) GetCompressedADRS() []byte {
	result := make([]byte, 0, 12)

	result = append(result, a.bytes[3:4]...)
	result = append(result, a.bytes[8:16]...)
	result = append(result, a.bytes[19:20]...)
	result = append(result, a.bytes[20:32]...)

	return result
}

func (a *ADRS) Copy() *ADRS {
	newAddr := make([]byte, len(a.bytes))
	copy(newAddr, a.bytes)
	return &ADRS{bytes: newAddr}
}
