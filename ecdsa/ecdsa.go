package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	pktweaktype "github.com/zhiqiangxu/pktweak-type"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type tweaker struct {
	curve            elliptic.Curve
	tweakedPK, tweak *ecdsa.PrivateKey
}

var _ pktweaktype.Tweaker = (*tweaker)(nil)

var ErrCurveNotSupported = errors.New("curve not supported")

func NewTweaker(curve elliptic.Curve) (pktweaktype.Tweaker, error) {
	switch curve {
	case btcec.S256(), elliptic.P256():
		return &tweaker{curve: curve}, nil
	default:
		return nil, ErrCurveNotSupported
	}
}

func ToPrivateKey(curve elliptic.Curve, d *big.Int) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	dBytes := d.Bytes()
	if 8*len(dBytes) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(dBytes)
	zeroSlice32(dBytes)

	// The priv.D must < N
	if priv.D.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(dBytes)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}

	return priv, nil
}

// this function computes a+b mod n
func computeAddMod(a, b, n *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, b), n)
}

func (t *tweaker) Tweak(realPK, tweak *big.Int) *big.Int {

	return computeAddMod(realPK, tweak, t.curve.Params().N)

}

func (t *tweaker) Initialize(tweakedPK, tweak *big.Int) (err error) {

	t.tweakedPK, err = ToPrivateKey(t.curve, tweakedPK)
	if err != nil {
		return
	}
	t.tweak, err = ToPrivateKey(t.curve, tweak)
	if err != nil {
		return
	}
	return nil
}

func (t *tweaker) Sign(hash []byte) (*pktweaktype.Signature, error) {

	if t.tweak == nil {
		return nil, fmt.Errorf("should call Initialize first")
	}

	switch t.curve {
	case btcec.S256():
		return t.computeECDSAK1EthSig(t.tweakedPK, t.tweak, hash)
	case elliptic.P256():
		return t.computeECDSAR1StdSig(t.tweakedPK, t.tweak, hash)
	default:
		return nil, ErrCurveNotSupported
	}
}

func (t *tweaker) computeECDSAR1StdSig(tweakedPK, tweak *ecdsa.PrivateKey, hash []byte) (*pktweaktype.Signature, error) {
	realPKBig := computeAddMod(tweakedPK.D, new(big.Int).Neg(tweak.D), t.curve.Params().N)
	realPK, err := ToPrivateKey(t.curve, realPKBig)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, realPK, hash)
	if err != nil {
		return nil, err
	}
	return &pktweaktype.Signature{Flavor: pktweaktype.STD, Value: &pktweaktype.ECDSAStdSig{R: r, S: s}}, nil
}

const (
	// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
	RecoveryIDOffset = 64
)

var zeroBytes = new(big.Int).Bytes()

// the returned signature is eth-flavored.
func (t *tweaker) computeECDSAK1EthSig(tweakedPK, tweak *ecdsa.PrivateKey, hash []byte) (*pktweaktype.Signature, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	realPKBig := computeAddMod(tweakedPK.D, new(big.Int).Neg(tweak.D), t.curve.Params().N)
	var realPK secp256k1.PrivateKey
	realPKBytes := realPKBig.Bytes()
	realPK.Key.SetByteSlice(realPKBytes)
	defer func() {
		realPKBig.SetBytes(zeroBytes)
		zeroSlice32(realPKBytes)
		realPK.Zero()
	}()

	sig := secp_ecdsa.SignCompact(&realPK, hash, false)

	// Convert to Ethereum signature format with 'recovery id' v at the end, opinionatedly.
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[RecoveryIDOffset] = v
	return &pktweaktype.Signature{Flavor: pktweaktype.ETH, Value: pktweaktype.ECDSAEthSig(sig)}, nil
}

var zero32 = [32]byte{}

// zeroSlice32 zeroes the provided 32-byte buffer.
func zeroSlice32(b []byte) {
	copy(b[:], zero32[:])
}
