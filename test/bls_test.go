package test

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
	"github.com/zhiqiangxu/pktweak/bls"
)

func TestBLS(t *testing.T) {
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	tweaker := bls.NewTweaker(dst)

	var ikm [32]byte
	rand.Read(ikm[:])
	realPK := blst.KeyGen(ikm[:])
	realPub := new(bls.PublicKey).From(realPK)

	rand.Read(ikm[:])
	tweakPK := blst.KeyGen(ikm[:])

	tweakedPK := tweaker.Tweak(new(big.Int).SetBytes(realPK.ToBEndian()), new(big.Int).SetBytes(tweakPK.ToBEndian()))

	tweaker.Initialize(tweakedPK, new(big.Int).SetBytes(tweakPK.ToBEndian()))
	msgHash, _ := hex.DecodeString("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")

	tweakerSig, err := tweaker.Sign(msgHash)
	require.Nil(t, err)

	require.True(t, tweakerSig.Value.(*bls.Signature).Verify(true, realPub, true, msgHash, dst, false))
}
