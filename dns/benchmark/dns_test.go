package main

import (
	"net"
	"testing"
)

func BenchmarkSizeValue(b *testing.B) {
	rdata := DNSRDATAA{Address: net.IPv4(192, 0, 2, 1)}
	for i := 0; i < b.N; i++ {
		rdata.SizeValue()
	}
}

func BenchmarkSizePointer(b *testing.B) {
	rdata := DNSRDATAA{Address: net.IPv4(192, 0, 2, 1)}
	for i := 0; i < b.N; i++ {
		rdata.SizePointer()
	}
}

func BenchmarkNewValue(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewValue()
	}
}

func BenchmarkNewPointer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewPointer()
	}
}
