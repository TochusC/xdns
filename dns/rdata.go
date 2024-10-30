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
	DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error)
}

// DNSRRRDATAFactory 函数根据 DNS 资源记录的类型返回对应的 RDATA 结构体。
func DNSRRRDATAFactory(rtype DNSType) DNSRRRDATA {
	switch rtype {
	case DNSRRTypeA:
		return &DNSRDATAA{}
	case DNSRRTypeNS:
		return &DNSRDATANS{}
	case DNSRRTypeCNAME:
		return &DNSRDATACNAME{}
	case DNSRRTypeTXT:
		return &DNSRDATATXT{}
	default:
		return &DNSRDATAUnknown{
			RRType: rtype,
			RData:  nil,
		}
	}

}

// DNSRDATAUnknown 结构体表示未知类型的 DNS 资源记录的 RDATA 部分。
// - 其包含一个 DNS 资源记录的类型和 RDATA 部分的字节切片。
type DNSRDATAUnknown struct {
	RRType DNSType
	RData  []byte
}

func (rdata *DNSRDATAUnknown) Type() DNSType {
	return rdata.RRType
}

func (rdata *DNSRDATAUnknown) Size() int {
	return len(rdata.RData)
}

func (rdata *DNSRDATAUnknown) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Unknown RDATA: ", rdata.RData,
	)
}

func (rdata *DNSRDATAUnknown) Encode() []byte {
	return rdata.RData
}

func (rdata *DNSRDATAUnknown) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than Unknown RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, rdata.RData)
	return rdata.Size(), nil
}

func (rdata *DNSRDATAUnknown) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	if len(buffer) < offset+rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than offset %d + Unknown RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.RData = buffer[offset:]
	return offset + rdata.Size(), nil
}

// A RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ADDRESS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSRDATAA 结构体表示 A 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含一个32位 IPv4 地址。
//
// RFC 1035 3.4.1 节 定义了 A 类型的 DNS 资源记录的 RDATA 部分的编码格式。
// 其 Type 值为 1。
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
		"Address: ", rdata.Address.String(),
	)
}

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
func (rdata *DNSRDATAA) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	if len(buffer) < offset+rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than offset %d + A RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.Address = net.IPv4(buffer[offset], buffer[offset+1], buffer[offset+2], buffer[offset+3])
	return offset + rdata.Size(), nil
}

// NS RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   NSDNAME                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSRDATANS 结构体表示 NS 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含一个 <domain-name> ，指向所查询区域的权威 DNS 服务器。
//
// RFC 1035 3.3.11 节 定义了 NS 类型的 DNS 资源记录。
// 其 Type 值为 2。
type DNSRDATANS struct {
	NSDNAME string
}

func (rdata *DNSRDATANS) Type() DNSType {
	return DNSRRTypeNS
}

func (rdata *DNSRDATANS) Size() int {
	return GetDomainNameWireLen(&rdata.NSDNAME)
}

func (rdata *DNSRDATANS) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"NS: ", rdata.NSDNAME,
	)
}

func (rdata *DNSRDATANS) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	_, err := EncodeDomainNameToBuffer(&rdata.NSDNAME, bytesArray)
	if err != nil {
		fmt.Println("function EncodeDomainNameToBuffer failed: ", err)
		os.Exit(1)
	}
	return bytesArray
}

func (rdata *DNSRDATANS) EncodeToBuffer(buffer []byte) (int, error) {
	rdataSize, err := EncodeDomainNameToBuffer(&rdata.NSDNAME, buffer)
	if err != nil {
		return -1, err
	}
	return rdataSize, nil
}

func (rdata *DNSRDATANS) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	rdata.NSDNAME, offset, err = DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, fmt.Errorf("decode NS failed: \n%v", err)
	}
	return offset, nil
}

// CNAME RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CNAME                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSRDATACNAME 结构体表示 CNAME 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含一个 <domain-name> ，指向所有者名称(Owner Name)的规范名称(Canonical Name)或主要名称(Primary Name)。
//     所有者名称是其指向名称的别名(Alias)。
//
// RFC 1035 3.3.1 节 定义了 CNAME 类型的 DNS 资源记录。
// 其 Type 值为 5。
type DNSRDATACNAME struct {
	CNAME string
}

func (rdata *DNSRDATACNAME) Type() DNSType {
	return DNSRRTypeCNAME
}

func (rdata *DNSRDATACNAME) Size() int {
	return GetDomainNameWireLen(&rdata.CNAME)
}

func (rdata *DNSRDATACNAME) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"CNAME: ", rdata.CNAME,
	)
}

func (rdata *DNSRDATACNAME) Encode() []byte {
	return EncodeDomainName(&rdata.CNAME)
}

func (rdata *DNSRDATACNAME) EncodeToBuffer(buffer []byte) (int, error) {
	len, err := EncodeDomainNameToBuffer(&rdata.CNAME, buffer)
	if err != nil {
		return -1, err
	}
	return len, nil
}

func (rdata *DNSRDATACNAME) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	rdata.CNAME, offset, err = DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, fmt.Errorf("decode CNAME failed: \n%v", err)
	}
	return offset, nil
}

// <character-string>: 一个长度字节后跟着字符序列，
// 长度字节指定了字符序列的长度，长度范围为 0-255，
// <character-string>的长度范围为 1~256，1表示空字符串。

// TXT RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   TXT-DATA                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSRDATATXT 结构体表示 TXT 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含<character-string>，用于存储任意文本信息，文本信息的语义(Semantics)由其区域定义。
//
// RFC 1035 3.3.14 节 定义了 TXT 类型的 DNS 资源记录。
// 其 Type 值为 16。
type DNSRDATATXT struct {
	// <character-string>
	TXT string
}

func (rdata *DNSRDATATXT) Type() DNSType {
	return DNSRRTypeTXT
}

func (rdata *DNSRDATATXT) Size() int {
	return GetCharacterStrWireLen(&rdata.TXT)
}

func (rdata *DNSRDATATXT) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"TXT: ", rdata.TXT,
	)
}

func (rTXT *DNSRDATATXT) Encode() []byte {
	return EncodeCharacterStr(&rTXT.TXT)
}

func (rdata *DNSRDATATXT) EncodeToBuffer(buffer []byte) (int, error) {
	return EncodeCharacterStrToBuffer(&rdata.TXT, buffer)
}

func (rdata *DNSRDATATXT) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	if len(buffer) < offset+rdata.Size() {
		return -1, fmt.Errorf("method *DNSRDATATXT DecodeFromBuffer failed: buffer length %d is less than offset %d + TXT RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.TXT = DecodeCharacterStr(buffer[offset : offset+rdLen])
	return offset + rdata.Size(), nil
}
