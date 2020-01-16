package orlped25519

type SHA512Context struct {
	c CGO_sha512_context
}

func NewSHA512Context() *SHA512Context {
	ctx := &SHA512Context{}
	err := CGO_sha512_init(&ctx.c)
	if err != nil {
		panic(err)
	}
	return ctx
}

func (ctx *SHA512Context) Update(msg []byte) {
	err := CGO_sha512_update(&ctx.c, msg)
	if err != nil {
		panic(err)
	}
}

func (ctx *SHA512Context) Final(out []byte) {
	err := CGO_sha512_final(&ctx.c, out)
	if err != nil {
		panic(err)
	}
}