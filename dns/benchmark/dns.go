package main

import (
	"net"
)

type DNSRDATAA struct {
	Address net.IP
}

func (rdata DNSRDATAA) SizeValue() int {
	return net.IPv4len
}

func (rdata *DNSRDATAA) SizePointer() int {
	return net.IPv4len
}

func NewValue() DNSRDATAA {
	return DNSRDATAA{Address: net.IPv4(192, 0, 2, 1)}
}

func NewPointer() *DNSRDATAA {
	return &DNSRDATAA{Address: net.IPv4(192, 0, 2, 1)}
}
