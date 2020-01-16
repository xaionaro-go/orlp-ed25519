package orlped25519

import (
	"reflect"
	"unsafe"
)

func bytesToCBytes(in []byte) unsafe.Pointer {
	return unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&in)).Data)
}
