// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// a.go 文件实现了 A 类型的 DNS 资源记录的 RDATA 编码。
package rdata

import (
	"fmt"
	"net"

	"github.com/tochusc/godns/dns"
)

// A RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ADDRESS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSARDATA 结构体表示 A 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含一个32位 IPv4 地址。
//
// RFC 1035 3.4.1 节 定义了 A 类型的 DNS 资源记录的 RDATA 部分的编码格式。
type DNSARDATA struct {
	Address net.IP
}

func (rdata *DNSARDATA) Type() dns.DNSType {
	return dns.DNSRRTypeA
}

func (rdata *DNSARDATA) Size() int {
	return net.IPv4len
}

func (rdata *DNSARDATA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Address: ", rdata.Address.String(), "\n",
		"### End of RDATA Section ###",
	)
}

// Encode 方法返回编码后的 RDATA 部分。
func (rdata *DNSARDATA) Encode() []byte {
	return rdata.Address.To4()
}

// EncodeToBuffer 方法将编码后的 RDATA 部分写入缓冲区。
// - 其接收 缓冲区切片 作为参数。
// - 返回值为 写入的字节数 和 错误信息。
// 如果缓冲区长度不足，返回 -1 和错误信息。
func (rdata *DNSARDATA) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than A RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, rdata.Encode())
	return rdata.Size(), nil
}
