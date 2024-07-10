package test

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"plugin"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	pktweaktype "github.com/zhiqiangxu/pktweak-type"
	ecdsa2 "github.com/zhiqiangxu/pktweak/ecdsa"
)

func TestECDSAK1(t *testing.T) {
	testECDSAK1WithFunc(t, ecdsa2.NewTweaker)
}

func TestECDSAK1Plugin(t *testing.T) {
	root, err := findRepoRoot(".")
	require.NoError(t, err)
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("cd %s && make pktweak", root))
	err = cmd.Run()
	require.NoError(t, err)
	p, err := plugin.Open(fmt.Sprintf("%s/pktweak.so", root))
	require.NoError(t, err)
	f, err := p.Lookup("NewECDSATweaker")
	require.NoError(t, err)
	testECDSAK1WithFunc(t, *f.(*func(curve elliptic.Curve) (pktweaktype.Tweaker, error)))
}

func testECDSAK1WithFunc(t *testing.T, f func(curve elliptic.Curve) (pktweaktype.Tweaker, error)) {
	tweaker, err := f(btcec.S256())
	require.Nil(t, err)

	realPK, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.Nil(t, err)
	tweakPK, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.Nil(t, err)
	tweakedPK := tweaker.Tweak(realPK.D, tweakPK.D)

	tweaker.Initialize(tweakedPK, tweakPK.D)
	msgHash, _ := hex.DecodeString("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")

	tweakerSig, err := tweaker.Sign(msgHash)
	require.Nil(t, err)
	realSig, err := crypto.Sign(msgHash, realPK)
	require.Nil(t, err)
	require.Equal(t, tweakerSig.Value, pktweaktype.ECDSAEthSig(realSig))
}

func TestECDSAR1(t *testing.T) {

	tweaker, err := ecdsa2.NewTweaker(elliptic.P256())
	require.Nil(t, err)

	realPK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	tweakPK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	tweakedPKBytes := tweaker.Tweak(realPK.D, tweakPK.D)

	tweaker.Initialize(tweakedPKBytes, tweakPK.D)
	msgHash, _ := hex.DecodeString("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")

	tweakerSig, err := tweaker.Sign(msgHash)
	require.Nil(t, err)
	stdSig := tweakerSig.Value.(*pktweaktype.ECDSAStdSig)
	ecdsa.Verify(&realPK.PublicKey, msgHash, stdSig.R, stdSig.S)
}

func findRepoRoot(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}
	for {
		modulePath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(modulePath); err == nil {
			return dir, nil
		}
		parentDir := filepath.Dir(dir)
		// Check if we reached the filesystem root
		if parentDir == dir {
			break
		}
		dir = parentDir
	}
	return "", fmt.Errorf("repo root not found")
}
