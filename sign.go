package orlped25519

func Sign(key PrivateKey, message []byte) (signature []byte) {
	signature = make([]byte, SignatureSize)
	CGO_ed25519_sign(signature, message, key.Public().(PublicKey), key)
	return
}
