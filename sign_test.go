package orlped25519_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	orlped25519 "github.com/xaionaro-go/orlp-ed25519"
)

func TestSign(t *testing.T) {
	_, key, err := ed25519.GenerateKey(zeroReader{})
	message := []byte("hello world!")
	assert.NoError(t, err)
	assert.Equal(t, ed25519.Sign(key, message), orlped25519.Sign([]byte(key), message))
}

func BenchmarkSign(b *testing.B) {
	b.ReportAllocs()
	pubkey, privkey, _ := ed25519.GenerateKey(zeroReader{})
	message := []byte("hello world!")
	signature := make([]byte, orlped25519.SignatureSize)

	b.ResetTimer()
	for i:=0; i<b.N; i++ {
		orlped25519.CGO_ed25519_sign(signature, message, pubkey, privkey)
	}
}