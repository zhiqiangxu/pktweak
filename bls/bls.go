package bls

import (
	"fmt"
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
	pktweaktype "github.com/zhiqiangxu/pktweak-type"
)

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

type tweaker struct {
	dst              []byte
	tweakedPK, tweak *blst.SecretKey
}

func NewTweaker(dst []byte) pktweaktype.Tweaker {

	return &tweaker{dst: dst}

}

func (t *tweaker) Tweak(realPK, tweak *big.Int) *big.Int {
	realPKScalar := new(blst.SecretKey).FromBEndian(realPK.Bytes())
	tweakScalar := new(blst.SecretKey).FromBEndian(tweak.Bytes())

	tweakedPK, _ := realPKScalar.Add(tweakScalar)

	return new(big.Int).SetBytes(tweakedPK.ToBEndian())
}

func (t *tweaker) Initialize(tweakedPK, tweak *big.Int) error {
	t.tweakedPK = new(blst.SecretKey).FromBEndian(tweakedPK.Bytes())

	t.tweak = new(blst.SecretKey).FromBEndian(tweak.Bytes())
	return nil
}

func (t *tweaker) Sign(hash []byte) (*pktweaktype.Signature, error) {
	if t.tweak == nil {
		return nil, fmt.Errorf("should call Initialize first")
	}

	realPK, _ := t.tweakedPK.Sub(t.tweak)
	defer realPK.Zeroize()
	sig := new(Signature).Sign(realPK, hash, t.dst, false)

	return &pktweaktype.Signature{Flavor: pktweaktype.SUPR, Value: sig}, nil
}
