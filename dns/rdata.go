// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// rdata.go 文件定义了用于表示 DNS 资源记录 RDATA 的接口 DNSRRRDATA。
package dns

import (
	"fmt"
	"net"
	"os"
)

// DNSRRRDATA 接口表示 DNS 资源记录的 RDATA 部分,
// 其常用方法：Size、String、Encode 和 EncodeToBuffer。
//
// RDATA 的具体格式取决于 DNS 资源记录的类型。
// 不同类型的 DNS 资源记录的 RDATA 部分的编码方式很不相同。
// 例如，
//   - 对于 A 类型的 DNS 资源记录，RDATA 部分为 4 字节的 IPv4 地址。
//   - 对于 MX 类型的 DNS 资源记录，RDATA 部分为 2 字节的优先级和一个域名。
//
// 为了实现RDATA的灵活性，于是 DNSRRRDATA 接口 应运而生,
// 任何实现了 DNSRRRDATA 接口的类型都可以作为 DNS 资源记录的 RDATA 部分。
type DNSRRRDATA interface {
	// Type 方法返回 RDATA 部分的类型。
	//  - 其返回值为 DNSType。
	// 许多对象（如 DNS 结构体） 与 DNSRRRDATA接口 都有着Size、String、Encode...等方法，
	// 但 DNS 结构体没有 Type 方法，而是直接定义了 DNSType 类型的 Type 字段 。
	// Type 方法特化了 DNSRRRDATA 接口使得 DNS 结构体等对象不是 DNSRRRDATA 接口的实现。
	Type() DNSType

	// Size 方法返回 RDATA 部分的大小。
	//  - 其返回值为 RDATA 部分的*准确*大小。
	Size() int

	// String 方法以*易读的形式*返回对应 资源记录 RDATA 部分的 字符串表示。
	//  - 其返回值为 RDATA 部分的字符串表示。
	String() string

	/* TODO: Mais 等到真正需要时再实现吧？
	// Masterlize 方法以*Master File中的ASCII表示*返回对应 资源记录 RDATA 部分的 字符串表示。
	//  - 其返回值为 RDATA 部分的字符串表示。
	Masterlize() string
	*/

	// Encode 方法返回编码后的 RDATA 部分。
	//  - 其返回值为 编码后的字节切片。
	Encode() []byte

	// EncodeToBuffer 方法将编码后的 RDATA 部分写入缓冲区。
	//  - 其接收 缓冲区切片 作为参数。
	//  - 返回值为 写入的字节数 和 错误信息。
	EncodeToBuffer(buffer []byte) (int, error)

	// DecodeFromBuffer 方法从包含 DNS消息 的缓冲区中解码 RDATA 部分。
	//  - 其接收 缓冲区, 偏移量 作为参数。
	//  - 返回值为 解码后的偏移量 和 错误信息。
	//
	// 如果出现错误，返回 -1, 及 相应报错 。
	DecodeFromBuffer(buffer []byte, offset int) (int, error)
}

// A RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ADDRESS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSRDATAA 结构体表示 A 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含一个32位 IPv4 地址。
//
// RFC 1035 3.4.1 节 定义了 A 类型的 DNS 资源记录的 RDATA 部分的编码格式。
type DNSRDATAA struct {
	Address net.IP
}

func (rdata *DNSRDATAA) Type() DNSType {
	return DNSRRTypeA
}

func (rdata *DNSRDATAA) Size() int {
	return net.IPv4len
}

func (rdata *DNSRDATAA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Address: ", rdata.Address.String(), "\n",
		"### End of RDATA Section ###",
	)
}

// Encode 方法返回编码后的 RDATA 部分。
func (rdata *DNSRDATAA) Encode() []byte {
	return rdata.Address.To4()
}

// EncodeToBuffer 方法将编码后的 RDATA 部分写入缓冲区。
//   - 其接收 缓冲区切片 作为参数。
//   - 返回值为 写入的字节数 和 错误信息。
//
// 如果缓冲区长度不足，返回 -1 和错误信息。
func (rdata *DNSRDATAA) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than A RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, rdata.Encode())
	return rdata.Size(), nil
}

// DecodeFromBuffer 方法从包含 DNS消息 的缓冲区中解码 RDATA 部分。
//   - 其接收 缓冲区, 偏移量 作为参数。
//   - 返回值为 解码后的偏移量 和 错误信息。
//
// 如果出现错误，返回 -1, 及 相应报错 。
func (rdata *DNSRDATAA) DecodeFromBuffer(buffer []byte, offset int) (int, error) {
	if len(buffer) < offset+rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than offset %d + A RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.Address = net.IPv4(buffer[offset], buffer[offset+1], buffer[offset+2], buffer[offset+3])
	return offset + rdata.Size(), nil
}

// NS RDATA 编码格式
type DNSNSRDATA struct {
	NS string
}

func (rdata *DNSNSRDATA) Type() DNSType {
	return DNSRRTypeNS
}

func (rdata *DNSNSRDATA) Size() int {
	return GetNameWireLength(&rdata.NS)
}

func (rdata *DNSNSRDATA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"NS: ", rdata.NS, "\n",
		"### End of RDATA Section ###",
	)
}

func (rdata *DNSNSRDATA) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	_, err := EncodeDomainNameToBuffer(&rdata.NS, bytesArray)
	if err != nil {
		fmt.Println("EncodeDomainNameToBuffer failed: ", err)
		os.Exit(1)
	}
	return bytesArray
}

func (rdata *DNSNSRDATA) EncodeToBuffer(buffer []byte) (int, error) {
	rdataSize := rdata.Size()
	if len(buffer) < rdataSize {
		return -1, fmt.Errorf("buffer length %d is less than NS RDATA size %d", len(buffer), rdataSize)
	}
	_, err := EncodeDomainNameToBuffer(&rdata.NS, buffer)
	if err != nil {
		return -1, err
	}
	return rdataSize, nil
}

// CNAME RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CNAME                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSCNAMERDATA 结构体表示 CNAME 类型的 DNS 资源记录的 RDATA 部分。
// - 其包含一个域名。
// RFC 1035 3.3.1 节 定义了 CNAME 类型的 DNS 资源记录。
// 其 Type 值为 5。
type DNSCNAMERDATA struct {
	CNAME string
}

func (rdata *DNSCNAMERDATA) Type() DNSType {
	return DNSRRTypeCNAME
}

func (rdata *DNSCNAMERDATA) Size() int {
	return len(rdata.CNAME) + 1
}

func (rdata *DNSCNAMERDATA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"CNAME: ", rdata.CNAME, "\n",
		"### End of RDATA Section ###",
	)
}

func (rdata *DNSCNAMERDATA) Encode() []byte {
	return []byte(rdata.CNAME)
}

func (rdata *DNSCNAMERDATA) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than CNAME RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, rdata.Encode())
	return rdata.Size(), nil
}

func InitDNSRRRDATA(rtype DNSType) DNSRRRDATA {
	switch rtype {
	case DNSRRTypeA:
		return &DNSRDATAA{}
	}
	return nil
}
