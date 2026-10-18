package main
var sink int64
//go:noinline
func nativeGo(first, second int64) int64 { return first+second }
func main() { sink=nativeGo(11,22) }
