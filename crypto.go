package topology // import "github.com/nathanaelle/wireguard-topology"

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// WGKeyLen is the length of a Curve25519 key
const WGKeyLen int = 32

func genKey() ([WGKeyLen]byte, error) {
	var secret [WGKeyLen]byte

	_, err := rand.Read(secret[:])

	// clamping : see  github.com/wireguard/wireguard-tools/src/genkey.c
	secret[0] &= 248
	secret[31] = (secret[31] & 127) | 64

	return secret, err
}

// GenPSK generate en base64 encoded PreSharedKey
func GenPSK() (psk string, err error) {
	var key [WGKeyLen]byte

	if key, err = genKey(); err != nil {
		return
	}

	psk = base64.RawStdEncoding.WithPadding('=').EncodeToString(key[:])

	return
}

// GenKeyPair generates a pair of base64 encoded Curve25519 keys
func GenKeyPair() (priv string, pub string, err error) {
	var secret [WGKeyLen]byte
	var public [WGKeyLen]byte

	if secret, err = genKey(); err != nil {
		return
	}

	curve25519.ScalarBaseMult(&public, &secret)

	priv = base64.RawStdEncoding.WithPadding('=').EncodeToString(secret[:])
	pub = base64.RawStdEncoding.WithPadding('=').EncodeToString(public[:])

	return
}
