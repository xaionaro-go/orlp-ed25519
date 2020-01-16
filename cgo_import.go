package orlped25519

// #cgo CFLAGS: -O0
// #include "./internal/implementation/src/fe.h"
// #include "./internal/implementation/src/fixedint.h"
// #include "./internal/implementation/src/ge.h"
// #include "./internal/implementation/src/sc.h"
// #include "./internal/implementation/src/sha512.h"
// #include "./internal/implementation/src/add_scalar.c"
// #include "./internal/implementation/src/fe.c"
// #include "./internal/implementation/src/ge.c"
// #include "./internal/implementation/src/key_exchange.c"
// #include "./internal/implementation/src/keypair.c"
// #include "./internal/implementation/src/sc.c"
// #include "./internal/implementation/src/seed.c"
// #include "./internal/implementation/src/sha512.c"
// #include "./internal/implementation/src/sign.c"
// #include "./internal/implementation/src/verify.c"
import "C"
import (
	"fmt"
)

func CGO_ed25519_sign(
	out_signature []byte,
	in_message []byte,
	in_pubkey []byte,
	in_privkey []byte,
) {
	if len(out_signature) != SignatureSize {
		panic("invalid signature size")
	}
	if len(in_pubkey) != PublicKeySize {
		panic("invalid pubkey size")
	}
	if len(in_privkey) != PrivateKeySize {
		panic("invalid privkey size")
	}
	C.ed25519_sign(
		(*C.uchar)(bytesToCBytes(out_signature)),
		(*C.uchar)(bytesToCBytes(in_message)),
		(C.ulong)(len(in_message)),
		(*C.uchar)(bytesToCBytes(in_pubkey)),
		(*C.uchar)(bytesToCBytes(in_privkey)),
	)
}

func CGO_ed25519_derive_public(out_pubkey []byte, in_privkey []byte) {
	if len(out_pubkey) != PublicKeySize {
		panic("invalid pubkey size")
	}
	if len(in_privkey) != PrivateKeySize {
		panic("invalid privkey size")
	}
	C.ed25519_derive_public(
		(*C.uchar)(bytesToCBytes(out_pubkey)),
		(*C.uchar)(bytesToCBytes(in_privkey)),
	)
}

func CGO_sha512(in_message []byte, out_hash []byte) error {
	// int sha512(const unsigned char *message, size_t message_len, unsigned char *out)
	rc := C.sha512(
		(*C.uchar)(bytesToCBytes(in_message)),
		(C.ulong)(len(in_message)),
		(*C.uchar)(bytesToCBytes(out_hash)),
	)
	if rc != 0 {
		return fmt.Errorf("an error: %v", rc)
	}
	return nil
}

type CGO_sha512_context = C.sha512_context

func CGO_sha512_init(ctx *CGO_sha512_context) error {
	rc := C.sha512_init(ctx)
	if rc != 0 {
		return fmt.Errorf("an error: %v", rc)
	}
	return nil
}

func CGO_sha512_update(ctx *CGO_sha512_context, in_msg []byte) error {
	rc := C.sha512_update(ctx, (*C.uchar)(bytesToCBytes(in_msg)), (C.ulong)(len(in_msg)))
	if rc != 0 {
		return fmt.Errorf("an error: %v", rc)
	}
	return nil
}


func CGO_sha512_final(ctx *CGO_sha512_context, out_hash []byte) error {
	rc := C.sha512_final(ctx, (*C.uchar)(bytesToCBytes(out_hash)))
	if rc != 0 {
		return fmt.Errorf("an error: %v", rc)
	}
	return nil
}
