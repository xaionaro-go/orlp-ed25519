package orlped25519

import (
	"crypto"
)

type PublicKey []byte

func (key PrivateKey) Public() crypto.PublicKey {
	pubkey := PublicKey(make([]byte, PublicKeySize))
	CGO_ed25519_derive_public(pubkey, key)
	return pubkey
}