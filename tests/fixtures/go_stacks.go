package main

import (
	"os"
	"runtime"
	"syscall"
)

//go:noinline
func leaf() { syscall.Write(1, []byte("GO_MARKER\n")) }

//go:noinline
func caller() { leaf() }

//go:noinline
func parkedLeaf(ready chan struct{}, wait chan struct{}) { close(ready); <-wait }

//go:noinline
func parkedCaller(ready chan struct{}, wait chan struct{}) { parkedLeaf(ready, wait) }

var sink uint64

//go:noinline
func busyLeaf() {
	for i := 0; i < 300000000; i++ {
		sink += uint64(i)
	}
}

//go:noinline
func busyCaller() {
	for i := 0; i < 4; i++ {
		busyLeaf()
	}
}

func main() {
	if len(os.Args) > 1 {
		busyCaller()
		return
	}

	ready, wait := make(chan struct{}), make(chan struct{})
	go parkedCaller(ready, wait)
	<-ready
	for i := 0; i < 10; i++ {
		runtime.Gosched()
	}
	caller()
}
