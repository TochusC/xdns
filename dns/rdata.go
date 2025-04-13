// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// rdata.go 文件定义了用于表示 DNS 资源记录 RDATA 的接口 DNSRRRDATA。

package dns

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
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

	// Equal 方法判断两个 RDATA 部分是否相等。
	//  - 其接收一个 DNSRRRDATA 类型的参数。
	//  - 其返回值为 两个 RDATA 部分是否相等。
	//
	Equal(DNSRRRDATA) bool

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
	// 其接受参数为：
	//  - 缓冲区
	//  - 偏移量
	//  - RDATA 部分的长度，对于某些不依赖RDLEN的RDATA，可传入0。
	// 返回值为：
	//  - 解码后的偏移量
	//  - 错误信息
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

func (rdata *DNSRDATAUnknown) Equal(rr DNSRRRDATA) bool {
	rru, ok := rr.(*DNSRDATAUnknown)
	if !ok {
		return false
	}
	return rdata.RRType == rru.RRType && bytes.Equal(rdata.RData, rru.RData)
}

func (rdata *DNSRDATAUnknown) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("method DNSRDATAUnknown EncodeToBuffer failed: buffer length %d is less than Unknown RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, rdata.RData)
	return rdata.Size(), nil
}

func (rdata *DNSRDATAUnknown) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	if len(buffer) < offset+rdata.Size() {
		return -1, fmt.Errorf("method DNSRDATAUnknown DecodeFromBuffer failed: buffer length %d is less than offset %d + Unknown RDATA size %d", len(buffer), offset, rdata.Size())
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

func (rdata *DNSRDATAA) Equal(rr DNSRRRDATA) bool {
	rra, ok := rr.(*DNSRDATAA)
	if !ok {
		return false
	}
	return rdata.Address.Equal(rra.Address)
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
		return -1, fmt.Errorf("method DNSRDATAA EncodeToBuffer failed: buffer length %d is less than A RDATA size %d", len(buffer), rdata.Size())
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
		return -1, fmt.Errorf("method DNSRDATAA DecodeFromBuffer failed: buffer length %d is less than offset %d + A RDATA size %d", len(buffer), offset, rdata.Size())
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

func (rdata *DNSRDATANS) Equal(rr DNSRRRDATA) bool {
	rrns, ok := rr.(*DNSRDATANS)
	if !ok {
		return false
	}
	return rdata.NSDNAME == rrns.NSDNAME
}

func (rdata *DNSRDATANS) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	_, err := EncodeDomainNameToBuffer(&rdata.NSDNAME, bytesArray)
	if err != nil {
		panic(fmt.Sprintf("method DNSRDATANS Encode failed: encode NSDNAME failed.\n%v", err))
	}
	return bytesArray
}

func (rdata *DNSRDATANS) EncodeToBuffer(buffer []byte) (int, error) {
	rdataSize, err := EncodeDomainNameToBuffer(&rdata.NSDNAME, buffer)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATANS EncodeToBuffer failed: encode NSDNAME failed.\n%v", err)
	}
	return rdataSize, nil
}

func (rdata *DNSRDATANS) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	rdata.NSDNAME, offset, err = DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATANS DecodeFromBuffer failed: decode NSDNAME failed.\n%v", err)
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

func (rdata *DNSRDATACNAME) Equal(rr DNSRRRDATA) bool {
	rrcname, ok := rr.(*DNSRDATACNAME)
	if !ok {
		return false
	}
	return rdata.CNAME == rrcname.CNAME
}

func (rdata *DNSRDATACNAME) Encode() []byte {
	return EncodeDomainName(&rdata.CNAME)
}

func (rdata *DNSRDATACNAME) EncodeToBuffer(buffer []byte) (int, error) {
	len, err := EncodeDomainNameToBuffer(&rdata.CNAME, buffer)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATACNAME EncodeToBuffer failed: encode CNAME failed.\n%v", err)
	}
	return len, nil
}

func (rdata *DNSRDATACNAME) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	rdata.CNAME, offset, err = DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATACNAME DecodeFromBuffer failed: decode CNAME failed.\n%v", err)
	}
	return offset, nil
}

// SOA RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     MNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     RNAME                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    SERIAL                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    REFRESH                    |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     RETRY                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    EXPIRE                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    MINIMUM                    |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type DNSRDATASOA struct {
	// <domain-name> MNAME
	MName string
	// <domain-name> RNAME
	RName string
	// <serial-number> SERIAL
	Serial uint32
	// <refresh-interval> REFRESH
	Refresh uint32
	// <retry-interval> RETRY
	Retry uint32
	// <expire-limit> EXPIRE
	Expire uint32
	// <minimum> MINIMUM
	Minimum uint32
}

func (rdata *DNSRDATASOA) Type() DNSType {
	return DNSRRTypeSOA
}

func (rdata *DNSRDATASOA) Size() int {
	return GetDomainNameWireLen(&rdata.MName) +
		GetDomainNameWireLen(&rdata.RName) +
		4*5 // 4 bytes for each of SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
}

func (rdata *DNSRDATASOA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"MName: ", rdata.MName,
		"\nRName: ", rdata.RName,
		"\nSerial: ", rdata.Serial,
		"\nRefresh: ", rdata.Refresh,
		"\nRetry: ", rdata.Retry,
		"\nExpire: ", rdata.Expire,
		"\nMinimum: ", rdata.Minimum,
	)
}

func (rdata *DNSRDATASOA) Equal(rr DNSRRRDATA) bool {
	rrsoa, ok := rr.(*DNSRDATASOA)
	if !ok {
		return false
	}
	return rdata.MName == rrsoa.MName &&
		rdata.RName == rrsoa.RName &&
		rdata.Serial == rrsoa.Serial &&
		rdata.Refresh == rrsoa.Refresh &&
		rdata.Retry == rrsoa.Retry &&
		rdata.Expire == rrsoa.Expire &&
		rdata.Minimum == rrsoa.Minimum
}

func (rdata *DNSRDATASOA) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	offset := 0
	nLen, err := EncodeDomainNameToBuffer(&rdata.MName, bytesArray[offset:])
	if err != nil {
		panic(fmt.Sprintf("method DNSRDATASOA Encode failed: encode MName failed.\n%v", err))
	}
	offset += nLen
	nLen, err = EncodeDomainNameToBuffer(&rdata.RName, bytesArray[offset:])
	offset += nLen
	if err != nil {
		panic(fmt.Sprintf("method DNSRDATASOA Encode failed: encode RName failed.\n%v", err))
	}
	binary.BigEndian.PutUint32(bytesArray[offset+4:], rdata.Serial)
	binary.BigEndian.PutUint32(bytesArray[offset+8:], rdata.Refresh)
	binary.BigEndian.PutUint32(bytesArray[offset+12:], rdata.Retry)
	binary.BigEndian.PutUint32(bytesArray[offset+16:], rdata.Expire)
	binary.BigEndian.PutUint32(bytesArray[offset+20:], rdata.Minimum)
	return bytesArray
}

func (rdata *DNSRDATASOA) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < 20 {
		return -1, fmt.Errorf("method DNSRDATASOA EncodeToBuffer failed: buffer length %d is less than SOA RDATA size %d", len(buffer), rdata.Size())
	}
	offset := 0
	nLen, err := EncodeDomainNameToBuffer(&rdata.MName, buffer[offset:])
	offset += nLen
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATASOA EncodeToBuffer failed: encode MName failed.\n%v", err)
	}
	nLen, err = EncodeDomainNameToBuffer(&rdata.RName, buffer[offset:])
	offset += nLen
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATASOA EncodeToBuffer failed: encode RName failed.\n%v", err)
	}
	binary.BigEndian.PutUint32(buffer[offset:], rdata.Serial)
	binary.BigEndian.PutUint32(buffer[offset+4:], rdata.Refresh)
	binary.BigEndian.PutUint32(buffer[offset+8:], rdata.Retry)
	binary.BigEndian.PutUint32(buffer[offset+12:], rdata.Expire)
	binary.BigEndian.PutUint32(buffer[offset+16:], rdata.Minimum)
	return offset + 20, nil
}

func (rdata *DNSRDATASOA) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	nLen := 0

	rdata.MName, nLen, err = DecodeDomainNameFromBuffer(buffer, offset)
	offset += nLen
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATASOA DecodeFromBuffer failed: decode MName failed.\n%v", err)
	}

	rdata.RName, nLen, err = DecodeDomainNameFromBuffer(buffer, offset)
	offset += nLen
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATASOA DecodeFromBuffer failed: decode RName failed.\n%v", err)
	}

	rdata.Serial = binary.BigEndian.Uint32(buffer[offset : offset+4])
	offset += 4
	rdata.Refresh = binary.BigEndian.Uint32(buffer[offset : offset+4])
	offset += 4
	rdata.Retry = binary.BigEndian.Uint32(buffer[offset : offset+4])
	offset += 4
	rdata.Expire = binary.BigEndian.Uint32(buffer[offset : offset+4])
	offset += 4
	rdata.Minimum = binary.BigEndian.Uint32(buffer[offset : offset+4])
	offset += 4
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

func (rdata *DNSRDATATXT) Equal(rr DNSRRRDATA) bool {
	rrtxt, ok := rr.(*DNSRDATATXT)
	if !ok {
		return false
	}
	return rdata.TXT == rrtxt.TXT
}

func (rTXT *DNSRDATATXT) Encode() []byte {
	return EncodeCharacterStr(&rTXT.TXT)
}

func (rdata *DNSRDATATXT) EncodeToBuffer(buffer []byte) (int, error) {
	sz, err := EncodeCharacterStrToBuffer(&rdata.TXT, buffer)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATATXT EncodeToBuffer failed: encode TXT failed.\n%v", err)
	}
	return sz, nil
}

func (rdata *DNSRDATATXT) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	rdEnd := offset + rdLen
	if len(buffer) < rdEnd {
		return -1, fmt.Errorf("method DNSRDATATXT DecodeFromBuffer failed: buffer length %d is less than offset %d + TXT RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.TXT = DecodeCharacterStr(buffer[offset:rdEnd])
	return offset + rdata.Size(), nil
}

// RRSIG RDATA 编码格式
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Type Covered        |   Algorithm   |     Labels     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Original TTL                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Expiration                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Inception                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Key Tag           |                                /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          Signer’s Name        /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                         						/
// /                            Signature                          /
// / 																/
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// DNSRRSIGRDATA 结构体表示 RRSIG 类型的 DNS 资源记录的 RDATA 部分。
//   - 其包含以下字段：
//   - TypeCovered: 16位无符号整数，表示被签名的资源记录的类型。
//   - Algorithm: 8位无符号整数，表示签名算法。
//   - Labels: 8位无符号整数，表示签名域名的标签数。
//   - OriginalTTL: 32位无符号整数，表示被签名资源记录的 TTL。
//   - Expiration: 32位无符号整数，表示签名过期时间。
//   - Inception: 32位无符号整数，表示签名生效时间。
//   - KeyTag: 16位无符号整数，表示签名公钥的 Key Tag。
//   - SignerName: 字符串，表示签名者名称。
//   - Signature: 字节切片，表示签名。
//
// RFC 4034 3.1 节 定义了 RRSIG 类型的 DNS 资源记录的 RDATA 部分的编码格式。
// 其 Type 值为 46。
type DNSRDATARRSIG struct {
	TypeCovered                        DNSType
	Algorithm                          DNSSECAlgorithm
	Labels                             uint8
	OriginalTTL, Expiration, Inception uint32
	KeyTag                             uint16
	SignerName                         string
	Signature                          []byte
}

func (rdata *DNSRDATARRSIG) Type() DNSType {
	return DNSRRTypeRRSIG
}

func (rdata *DNSRDATARRSIG) Size() int {
	return 18 + GetDomainNameWireLen(&rdata.SignerName) + len(rdata.Signature)
}

func (rdata *DNSRDATARRSIG) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Type Covered: ", rdata.TypeCovered,
		"\nAlgorithm: ", rdata.Algorithm,
		"\nLabels: ", rdata.Labels,
		"\nOriginal TTL: ", rdata.OriginalTTL,
		"\nExpiration: ", rdata.Expiration,
		"\nInception: ", rdata.Inception,
		"\nKey Tag: ", rdata.KeyTag,
		"\nSigner Name: ", rdata.SignerName,
		"\nSignature: ", rdata.Signature,
	)
}

func (rdata *DNSRDATARRSIG) Equal(rr DNSRRRDATA) bool {
	rrsig, ok := rr.(*DNSRDATARRSIG)
	if !ok {
		return false
	}
	return rdata.TypeCovered == rrsig.TypeCovered &&
		rdata.Algorithm == rrsig.Algorithm &&
		rdata.Labels == rrsig.Labels &&
		rdata.OriginalTTL == rrsig.OriginalTTL &&
		rdata.Expiration == rrsig.Expiration &&
		rdata.Inception == rrsig.Inception &&
		rdata.KeyTag == rrsig.KeyTag &&
		rdata.SignerName == rrsig.SignerName &&
		bytes.Equal(rdata.Signature, rrsig.Signature)
}

func (rdata *DNSRDATARRSIG) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	binary.BigEndian.PutUint16(bytesArray, uint16(rdata.TypeCovered))
	bytesArray[2] = byte(rdata.Algorithm)
	bytesArray[3] = rdata.Labels
	binary.BigEndian.PutUint32(bytesArray[4:], rdata.OriginalTTL)
	binary.BigEndian.PutUint32(bytesArray[8:], rdata.Expiration)
	binary.BigEndian.PutUint32(bytesArray[12:], rdata.Inception)
	binary.BigEndian.PutUint16(bytesArray[16:], uint16(rdata.KeyTag))
	offset, _ := EncodeDomainNameToBuffer(&rdata.SignerName, bytesArray[18:])
	copy(bytesArray[offset+18:], rdata.Signature)
	return bytesArray
}

func (rdata *DNSRDATARRSIG) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than RRSIG RDATA size %d", len(buffer), rdata.Size())
	}
	binary.BigEndian.PutUint16(buffer, uint16(rdata.TypeCovered))
	buffer[2] = byte(rdata.Algorithm)
	buffer[3] = rdata.Labels
	binary.BigEndian.PutUint32(buffer[4:], rdata.OriginalTTL)
	binary.BigEndian.PutUint32(buffer[8:], rdata.Expiration)
	binary.BigEndian.PutUint32(buffer[12:], rdata.Inception)
	binary.BigEndian.PutUint16(buffer[16:], uint16(rdata.KeyTag))
	offset, err := EncodeDomainNameToBuffer(&rdata.SignerName, buffer[18:])
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATARRSIG EncodeToBuffer failed: encode RRSIG Signer Name failed.\n%v", err)
	}
	copy(buffer[offset+18:], rdata.Signature)
	return rdata.Size(), nil
}

func (rdata *DNSRDATARRSIG) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	if rdLen < 18 {
		return -1, fmt.Errorf("method DNSRDATARRSIG DecodeFromBuffer failed: RRSIG RDATA size %d is less than 18", rdLen)
	}
	if len(buffer) < offset+18 {
		return -1, fmt.Errorf("method DNSRDATARRSIG DecodeFromBuffer failed: buffer length %d is less than offset %d + RRSIG RDATA size %d", len(buffer), offset, rdata.Size())
	}
	var err error
	rdEnd := offset + rdLen
	rdata.TypeCovered = DNSType(binary.BigEndian.Uint16(buffer[offset:]))
	rdata.Algorithm = DNSSECAlgorithm(buffer[offset+2])
	rdata.Labels = buffer[offset+3]
	rdata.OriginalTTL = binary.BigEndian.Uint32(buffer[offset+4:])
	rdata.Expiration = binary.BigEndian.Uint32(buffer[offset+8:])
	rdata.Inception = binary.BigEndian.Uint32(buffer[offset+12:])
	rdata.KeyTag = binary.BigEndian.Uint16(buffer[offset+16:])
	rdata.SignerName, offset, err = DecodeDomainNameFromBuffer(buffer, offset+18)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATARRSIG DecodeFromBuffer failed: decode RRSIG Signer Name failed.\n%v", err)
	}
	copy(rdata.Signature, buffer[offset:rdEnd])
	return rdEnd, nil
}

// DNSKEY RDATA 编码格式
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Flags            |    Protocol   |    Algorithm   |                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                           Public Key                          /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// DNSRRSIGRDATA 结构体表示 DNSKEY 类型的 DNS 资源记录的 RDATA 部分。
// 其包含以下字段：
//   - Flags: 16位无符号整数，表示密钥类型。
//   - Protocol: 8位无符号整数，表示密钥协议。
//   - Algorithm: 8位无符号整数，表示密钥算法。
//   - PublicKey: 字节切片，表示密钥的原始字节形式（注意：不是Base64编码后的形式）。
//
// RFC 4034 2.1 节 定义了 DNSKEY 类型的 DNS 资源记录的 RDATA 部分的编码格式。
// 其 Type 值为 48。
type DNSRDATADNSKEY struct {
	Flags     DNSKEYFlag
	Protocol  DNSKEYProtocol
	Algorithm DNSSECAlgorithm
	PublicKey []byte
}

func (rdata *DNSRDATADNSKEY) Type() DNSType {
	return DNSRRTypeDNSKEY
}

func (rdata *DNSRDATADNSKEY) Size() int {
	return 4 + len(rdata.PublicKey)
}

func (rdata *DNSRDATADNSKEY) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Flags: ", rdata.Flags,
		"\nProtocol: ", rdata.Protocol,
		"\nAlgorithm: ", rdata.Algorithm,
		"\nPublic Key: ", rdata.PublicKey,
	)
}

func (rdata *DNSRDATADNSKEY) Equal(rr DNSRRRDATA) bool {
	rrkey, ok := rr.(*DNSRDATADNSKEY)
	if !ok {
		return false
	}
	return rdata.Flags == rrkey.Flags &&
		rdata.Protocol == rrkey.Protocol &&
		rdata.Algorithm == rrkey.Algorithm &&
		bytes.Equal(rdata.PublicKey, rrkey.PublicKey)
}

func (rdata *DNSRDATADNSKEY) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	binary.BigEndian.PutUint16(bytesArray, uint16(rdata.Flags))
	bytesArray[2] = uint8(rdata.Protocol)
	bytesArray[3] = uint8(rdata.Algorithm)
	copy(bytesArray[4:], rdata.PublicKey)
	return bytesArray
}

func (rdata *DNSRDATADNSKEY) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("method DNSRDATADNSKEY EncodeToBuffer failed: buffer length %d is less than DNSKEY RDATA size %d", len(buffer), rdata.Size())
	}
	binary.BigEndian.PutUint16(buffer, uint16(rdata.Flags))
	buffer[2] = uint8(rdata.Protocol)
	buffer[3] = byte(rdata.Algorithm)
	copy(buffer[4:], rdata.PublicKey)
	return rdata.Size(), nil
}

func (rdata *DNSRDATADNSKEY) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	rdEnd := offset + rdLen
	if rdLen < 4 {
		return -1, fmt.Errorf("method DNSRDATADNSKEY DecodeFromBuffer failed: DNSKEY RDATA size %d is less than 4", rdLen)
	}
	if len(buffer) < offset+4 {
		return -1, fmt.Errorf("method DNSRDATADNSKEY DecodeFromBuffer failed: buffer length %d is less than offset %d + DNSKEY RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.Flags = DNSKEYFlag(binary.BigEndian.Uint16(buffer[offset:]))
	rdata.Protocol = DNSKEYProtocol(buffer[offset+2])
	rdata.Algorithm = DNSSECAlgorithm(buffer[offset+3])
	copy(rdata.PublicKey, buffer[offset+4:rdEnd])
	return rdEnd, nil
}

// DS RDATA 编码格式
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Key Tag            |   Algorithm   |   Digest Type  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Digest                             /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// DNSRDATADS 结构体表示 DS 类型的 DNS 资源记录的 RDATA 部分。
// 其包含以下字段：
//   - KeyTag: 16位无符号整数，表示密钥标签。
//   - Algorithm: 8位无符号整数，表示密钥算法。
//   - DigestType: 8位无符号整数，表示摘要类型。
//   - Digest: 字节切片，表示摘要。
//
// RFC 4034 5.1 节 定义了 DS 类型的 DNS 资源记录的 RDATA 部分的编码格式。
// 其 Type 值为 43。
type DNSRDATADS struct {
	KeyTag     uint16
	Algorithm  DNSSECAlgorithm
	DigestType DNSSECDigestType
	Digest     []byte
}

func (rdata *DNSRDATADS) Type() DNSType {
	return DNSRRTypeDS
}

func (rdata *DNSRDATADS) Size() int {
	return 4 + len(rdata.Digest)
}

func (rdata *DNSRDATADS) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Key Tag: ", rdata.KeyTag,
		"\nAlgorithm: ", rdata.Algorithm,
		"\nDigest Type: ", rdata.DigestType,
		"\nDigest: ", rdata.Digest,
	)
}

func (rdata *DNSRDATADS) Equal(rr DNSRRRDATA) bool {
	rrds, ok := rr.(*DNSRDATADS)
	if !ok {
		return false
	}
	return rdata.KeyTag == rrds.KeyTag &&
		rdata.Algorithm == rrds.Algorithm &&
		rdata.DigestType == rrds.DigestType &&
		bytes.Equal(rdata.Digest, rrds.Digest)
}

func (rdata *DNSRDATADS) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	binary.BigEndian.PutUint16(bytesArray, rdata.KeyTag)
	bytesArray[2] = byte(rdata.Algorithm)
	bytesArray[3] = byte(rdata.DigestType)
	copy(bytesArray[4:], rdata.Digest)
	return bytesArray
}

func (rdata *DNSRDATADS) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("method DNSRDATADS EncodeToBuffer failed: buffer length %d is less than DS RDATA size %d", len(buffer), rdata.Size())
	}
	binary.BigEndian.PutUint16(buffer, rdata.KeyTag)
	buffer[2] = byte(rdata.Algorithm)
	buffer[3] = byte(rdata.DigestType)
	copy(buffer[4:], rdata.Digest)
	return rdata.Size(), nil
}

func (rdata *DNSRDATADS) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	rdEnd := offset + rdLen
	if rdLen < 4 {
		return -1, fmt.Errorf("method DNSRDATADS DecodeFromBuffer failed: DS RDATA size %d is less than 4", rdLen)
	}
	if len(buffer) < rdEnd {
		return -1, fmt.Errorf("method DNSRDATADS DecodeFromBuffer failed: buffer length %d is less than offset %d + DS RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.KeyTag = binary.BigEndian.Uint16(buffer[offset:])
	rdata.Algorithm = DNSSECAlgorithm(buffer[offset+2])
	rdata.DigestType = DNSSECDigestType(buffer[offset+3])
	copy(rdata.Digest, buffer[offset+4:rdEnd])
	return rdEnd, nil
}

// NSEC RDATA 编码格式
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Next Domain Name                        /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                        Type Bit Maps                          /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// DNSRDATANSEC 结构体表示 NSEC 类型的 DNS 资源记录的 RDATA 部分。
// 其包含以下字段：
//   - NextDomainName: 下一个域名。
//   - TypeBitMaps: 类型位图。
//
// RFC 4034 2.1 节 定义了 NSEC 类型的 DNS 资源记录的 RDATA 部分的编码格式。
// 其 Type 值为 47。
type DNSRDATANSEC struct {
	NextDomainName string
	// Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+
	TypeBitMaps []DNSType
}

func (rdata *DNSRDATANSEC) Type() DNSType {
	return DNSRRTypeNSEC
}

func (rdata *DNSRDATANSEC) Size() int {
	return GetDomainNameWireLen(&rdata.NextDomainName) + len(EncodeTypeBitMaps(rdata.TypeBitMaps))
}

func (rdata *DNSRDATANSEC) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Next Domain Name: ", rdata.NextDomainName,
		"\nType Bit Maps: ", rdata.TypeBitMaps,
	)
}

func EncodeTypeBitMaps(typeList []DNSType) []byte {
	var bytesArray []byte

	numericalList := make([]int, 0)
	for _, t := range typeList {
		numericalList = append(numericalList, int(t))
	}
	sort.Ints(numericalList)

	type bitMap struct {
		index  uint8
		length uint8
		bits   []byte
	}
	var typeBitMaps []bitMap

	tBitMap := bitMap{
		index:  0,
		length: 0,
		bits:   []byte{},
	}

	for _, t := range numericalList {
		if tBitMap.index < uint8(t/256) {
			if tBitMap.length > 0 {
				typeBitMaps = append(typeBitMaps, tBitMap)
			}
			tBitMap = bitMap{
				index:  uint8(t / 256),
				length: 0,
				bits:   []byte{},
			}
		}
		var temp []byte
		z := int(t) / 8

		for i := 0; i < z; i++ {
			temp = append(temp, 0)
		}
		temp = append(temp, 0x80>>(t%8))

		for i := 1; i <= len(temp); i++ {
			if i > int(tBitMap.length) {
				tBitMap.bits = append(tBitMap.bits, temp[i-1])
			} else {
				tBitMap.bits[i-1] |= temp[i-1]
			}
		}

		tBitMap.length = uint8(z + 1)
	}
	if tBitMap.length > 0 {
		typeBitMaps = append(typeBitMaps, tBitMap)
	}

	for _, t := range typeBitMaps {
		bytesArray = append(bytesArray, t.index)
		bytesArray = append(bytesArray, t.length)
		bytesArray = append(bytesArray, t.bits...)
	}

	return bytesArray
}

func (rdata *DNSRDATANSEC) Equal(rr DNSRRRDATA) bool {
	rrnsec, ok := rr.(*DNSRDATANSEC)
	if !ok {
		return false
	}

	typeList := make([]int, 0)
	sort.Ints(typeList)

	for _, t := range rdata.TypeBitMaps {
		typeList = append(typeList, int(t))
	}

	rrTypeList := make([]int, 0)
	for _, t := range rrnsec.TypeBitMaps {
		rrTypeList = append(rrTypeList, int(t))
	}
	sort.Ints(rrTypeList)

	if len(typeList) != len(rrTypeList) {
		return false
	}
	for i := 0; i < len(typeList); i++ {
		if typeList[i] != rrTypeList[i] {
			return false
		}
	}

	return rdata.NextDomainName == rrnsec.NextDomainName
}

// Encode 方法将 NSEC RDATA 编码为字节切片。
func (rdata *DNSRDATANSEC) Encode() []byte {
	nextDomainName := EncodeDomainName(&rdata.NextDomainName)
	typeBitMaps := EncodeTypeBitMaps(rdata.TypeBitMaps)
	bytesArray := make([]byte, len(nextDomainName)+len(typeBitMaps))
	copy(bytesArray, nextDomainName)
	copy(bytesArray[len(nextDomainName):], typeBitMaps)
	return bytesArray
}

func (rdata *DNSRDATANSEC) EncodeToBuffer(buffer []byte) (int, error) {
	nextDomainName := EncodeDomainName(&rdata.NextDomainName)
	typeBitMaps := EncodeTypeBitMaps(rdata.TypeBitMaps)
	size := len(nextDomainName) + len(typeBitMaps)
	if len(buffer) < size {
		return -1, fmt.Errorf("buffer length %d is less than NSEC RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, nextDomainName)
	copy(buffer[len(nextDomainName):], typeBitMaps)
	return rdata.Size(), nil
}

func DecodeTypeBitMaps(typeBitMaps []byte) []DNSType {
	var typeList []DNSType
	for i := 0; i < len(typeBitMaps); {
		index := int(typeBitMaps[i])
		length := int(typeBitMaps[i+1])
		for j := 0; j < int(length); j++ {
			for k := 0; k < 8; k++ {
				if typeBitMaps[i+2+j]&(0x80>>k) != 0 {
					typeList = append(typeList, DNSType(index*256+j*8+k))
				}
			}
		}
		i += 2 + int(length)
	}
	return typeList
}

func (rdata *DNSRDATANSEC) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	var rdEnd = offset + rdLen
	if len(buffer) < rdEnd {
		return -1, fmt.Errorf("method DNSRDATANSEC DecodeFromBuffer failed: buffer length %d is less than offset %d + NSEC RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.NextDomainName, offset, err = DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATANSEC DecodeFromBuffer failed: decode NSEC Next Domain Name failed.\n%v", err)
	}
	rdata.TypeBitMaps = DecodeTypeBitMaps(buffer[offset:rdEnd])
	return rdEnd, nil
}

// NSEC3 RDATA 编码格式
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.  | 	Flags 	| 			Iterations			   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length | 					Salt 		    	       /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Hash Length | 			Next Hashed Owner Name		       /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// / 						Type Bit Maps				 		   /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// DNSRDATANSEC3 结构体表示 NSEC3 类型的 DNS 资源记录的 RDATA 部分。
// 其包含以下字段：
//   - HashAlgorithm: 8位无符号整数，表示哈希算法。
//   - Flags: 8位无符号整数，表示标志。
//   - Iterations: 16位无符号整数，表示迭代次数。
//   - SaltLength: 8位无符号整数，表示Salt长度。
//   - Salt: 字符串，表示Salt。
//   - HashLength: 8位无符号整数，表示哈希长度。
//   - NextHashedOwnerName: 下一个哈希的所有名称。
//   - TypeBitMaps: 类型位图。
//
// RFC 5155 3.2 节 定义了 NSEC3 类型的 DNS 资源记录的 RDATA 部分的编码格式。
// 其 Type 值为 50。

type DNSRDATANSEC3 struct {
	HashAlgorithm       DNSSECDigestType
	Flags               NSEC3Flags
	Iterations          uint16
	SaltLength          uint8
	Salt                string
	HashLength          uint8
	NextHashedOwnerName string
	TypeBitMaps         []DNSType
}

type NSEC3Flags uint8

const (
	NSEC3FlagOptOut   NSEC3Flags = 1
	NSEC3FlagReserved NSEC3Flags = 0
)

func (rdata *DNSRDATANSEC3) Type() DNSType {
	return DNSRRTypeNSEC3
}

func (rdata *DNSRDATANSEC3) Size() int {
	saltBytes := []byte(rdata.Salt)
	nextHashOwnerName := rdata.HashOwnerName(rdata.NextHashedOwnerName)
	typeBitMaps := EncodeTypeBitMaps(rdata.TypeBitMaps)
	size := 6 + len(saltBytes) + len(nextHashOwnerName) + len(typeBitMaps)
	return size
}

func (rdata *DNSRDATANSEC3) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Hash Algorithm: ", rdata.HashAlgorithm,
		"\nFlags: ", rdata.Flags,
		"\nIterations: ", rdata.Iterations,
		"\nSalt Length: ", rdata.SaltLength,
		"\nSalt: ", rdata.Salt,
		"\nHash Length: ", rdata.HashLength,
		"\nNext Hashed Owner Name: ", rdata.NextHashedOwnerName,
		"\nType Bit Maps: ", rdata.TypeBitMaps,
	)
}

func (rdata *DNSRDATANSEC3) Equal(rr DNSRRRDATA) bool {
	rrnsec3, ok := rr.(*DNSRDATANSEC3)
	if !ok {
		return false
	}

	typeList := make([]int, 0)
	sort.Ints(typeList)

	for _, t := range rdata.TypeBitMaps {
		typeList = append(typeList, int(t))
	}

	rrTypeList := make([]int, 0)
	for _, t := range rrnsec3.TypeBitMaps {
		rrTypeList = append(rrTypeList, int(t))
	}
	sort.Ints(rrTypeList)

	if len(typeList) != len(rrTypeList) {
		return false
	}
	for i := 0; i < len(typeList); i++ {
		if typeList[i] != rrTypeList[i] {
			return false
		}
	}

	return rdata.HashAlgorithm == rrnsec3.HashAlgorithm &&
		rdata.Flags == rrnsec3.Flags &&
		rdata.Iterations == rrnsec3.Iterations &&
		rdata.Salt == rrnsec3.Salt &&
		rdata.NextHashedOwnerName == rrnsec3.NextHashedOwnerName
}

func (rdata *DNSRDATANSEC3) HashOwnerName(ownerName string) []byte {
	nextHashOwnerName := EncodeDomainName(&ownerName)
	switch rdata.HashAlgorithm {
	case DNSSECDigestTypeSHA1:
		for i := 0; i <= int(rdata.Iterations); i++ {
			digest := sha1.Sum(append(nextHashOwnerName, []byte(rdata.Salt)...))
			nextHashOwnerName = digest[:]
		}
		return nextHashOwnerName
	case DNSSECDigestTypeSHA256:
		for i := 0; i <= int(rdata.Iterations); i++ {
			digest := sha256.Sum256(append(nextHashOwnerName, []byte(rdata.Salt)...))
			nextHashOwnerName = digest[:]
		}
	case DNSSECDigestTypeSHA384:
		for i := 0; i <= int(rdata.Iterations); i++ {
			digest := sha512.Sum384(append(nextHashOwnerName, []byte(rdata.Salt)...))
			nextHashOwnerName = digest[:]
		}
	case DNSSECDigestTypeSHA512:
		for i := 0; i <= int(rdata.Iterations); i++ {
			digest := sha512.Sum512(append(nextHashOwnerName, []byte(rdata.Salt)...))
			nextHashOwnerName = digest[:]
		}
	}
	return nextHashOwnerName
}

func (rdata *DNSRDATANSEC3) Encode() []byte {
	bytesArray := make([]byte, 0)
	bytesArray = append(bytesArray, uint8(rdata.HashAlgorithm))
	bytesArray = append(bytesArray, uint8(rdata.Flags))
	bytesArray = append(bytesArray, byte(rdata.Iterations>>8), byte(rdata.Iterations))
	if rdata.SaltLength == 0 {
		bytesArray = append(bytesArray, uint8(len([]byte(rdata.Salt))))
	} else {
		bytesArray = append(bytesArray, rdata.SaltLength)
	}
	bytesArray = append(bytesArray, []byte(rdata.Salt)...)
	nextHashOwnerName := rdata.HashOwnerName(rdata.NextHashedOwnerName)
	if rdata.HashLength == 0 {
		bytesArray = append(bytesArray, uint8(len(nextHashOwnerName)))
	} else {
		bytesArray = append(bytesArray, rdata.HashLength)
	}
	bytesArray = append(bytesArray, nextHashOwnerName...)
	typeBitMaps := EncodeTypeBitMaps(rdata.TypeBitMaps)
	bytesArray = append(bytesArray, typeBitMaps...)
	return bytesArray
}

func (rdata *DNSRDATANSEC3) EncodeToBuffer(buffer []byte) (int, error) {
	saltBytes := []byte(rdata.Salt)
	nextHashOwnerName := rdata.HashOwnerName(rdata.NextHashedOwnerName)
	typeBitMaps := EncodeTypeBitMaps(rdata.TypeBitMaps)
	size := 6 + len(saltBytes) + len(nextHashOwnerName) + len(typeBitMaps)
	if len(buffer) < size {
		return -1, fmt.Errorf("buffer length %d is less than NSEC3 RDATA size %d", len(buffer), size)
	}
	buffer[0] = byte(rdata.HashAlgorithm)
	buffer[1] = uint8(rdata.Flags)
	binary.BigEndian.PutUint16(buffer[2:], rdata.Iterations)
	if rdata.SaltLength == 0 {
		buffer[4] = byte(len(saltBytes))
	} else {
		buffer[4] = rdata.SaltLength
	}
	copy(buffer[5:], saltBytes)
	if rdata.HashLength == 0 {
		buffer[5+len(saltBytes)] = byte(len(nextHashOwnerName))
	} else {
		buffer[5+len(saltBytes)] = rdata.HashLength
	}
	buffer[6+len(saltBytes)] = byte(len(nextHashOwnerName))
	copy(buffer[7+len(saltBytes):], nextHashOwnerName)
	copy(buffer[7+len(saltBytes)+len(nextHashOwnerName):], typeBitMaps)
	return size, nil
}

func (rdata *DNSRDATANSEC3) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	var err error
	var rdEnd = offset + rdLen
	if rdLen < 6 {
		return -1, fmt.Errorf("method DNSRDATANSEC3 DecodeFromBuffer failed: NSEC3 RDATA size %d is less than 6", rdLen)
	}
	if len(buffer) < rdEnd {
		return -1, fmt.Errorf("method DNSRDATANSEC3 DecodeFromBuffer failed: buffer length %d is less than offset %d + NSEC3 RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.HashAlgorithm = DNSSECDigestType(buffer[offset])
	rdata.Flags = NSEC3Flags(buffer[offset+1])
	rdata.Iterations = binary.BigEndian.Uint16(buffer[offset+2:])
	rdata.SaltLength = buffer[offset+4]
	rdata.Salt = string(buffer[offset+5 : offset+5+int(rdata.SaltLength)])
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATANSEC3 DecodeFromBuffer failed: decode NSEC3 Salt failed.\n%v", err)
	}
	offset += 5 + int(rdata.SaltLength)
	rdata.HashLength = buffer[offset]
	rdata.NextHashedOwnerName = base32.StdEncoding.EncodeToString(buffer[offset+1 : offset+1+int(rdata.HashLength)])
	if err != nil {
		return -1, fmt.Errorf("method DNSRDATANSEC3 DecodeFromBuffer failed: decode NSEC3 Next Hashed Owner Name failed.\n%v", err)
	}
	rdata.TypeBitMaps = DecodeTypeBitMaps(buffer[offset+1+int(rdata.HashLength) : rdEnd])
	return rdEnd, nil
}

// DNSKEY RDATA 编码格式
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// +0 (MSB)                            +1 (LSB)
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |                          OPTION-CODE                          |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |                         OPTION-LENGTH                         |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |                                                               |
// /                          OPTION-DATA                          /
// /                                                               /
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
type DNSRDATAOPT struct {
	OptionCode   uint16
	OptionLength uint16
	OptionData   []byte
}

func (rdata *DNSRDATAOPT) Type() DNSType {
	return DNSRRTypeOPT
}

func (rdata *DNSRDATAOPT) Size() int {
	return 4 + len(rdata.OptionData)
}

func (rdata *DNSRDATAOPT) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"Option Code: ", rdata.OptionCode,
		"\nOption Length: ", rdata.OptionLength,
		"\nOption Data: ", rdata.OptionData,
	)
}

func (rdata *DNSRDATAOPT) Equal(rr DNSRRRDATA) bool {
	rropt, ok := rr.(*DNSRDATAOPT)
	if !ok {
		return false
	}
	return rdata.OptionCode == rropt.OptionCode &&
		rdata.OptionLength == rropt.OptionLength &&
		bytes.Equal(rdata.OptionData, rropt.OptionData)
}

func (rdata *DNSRDATAOPT) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	binary.BigEndian.PutUint16(bytesArray, rdata.OptionCode)
	binary.BigEndian.PutUint16(bytesArray[2:], rdata.OptionLength)
	copy(bytesArray[4:], rdata.OptionData)
	return bytesArray
}

func (rdata *DNSRDATAOPT) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("method DNSRDATAOPT EncodeToBuffer failed: buffer length %d is less than OPT RDATA size %d", len(buffer), rdata.Size())
	}
	binary.BigEndian.PutUint16(buffer, rdata.OptionCode)
	binary.BigEndian.PutUint16(buffer[2:], rdata.OptionLength)
	copy(buffer[4:], rdata.OptionData)
	return rdata.Size(), nil
}

func (rdata *DNSRDATAOPT) DecodeFromBuffer(buffer []byte, offset int, rdLen int) (int, error) {
	rdEnd := offset + rdLen
	if rdLen < 4 {
		return -1, fmt.Errorf("method DNSRDATAOPT DecodeFromBuffer failed: OPT RDATA size %d is less than 4", rdLen)
	}
	if len(buffer) < rdEnd {
		return -1, fmt.Errorf("method DNSRDATAOPT DecodeFromBuffer failed: buffer length %d is less than offset %d + OPT RDATA size %d", len(buffer), offset, rdata.Size())
	}
	rdata.OptionCode = binary.BigEndian.Uint16(buffer[offset:])
	rdata.OptionLength = binary.BigEndian.Uint16(buffer[offset+2:])
	rdata.OptionData = make([]byte, rdLen-4)
	copy(rdata.OptionData, buffer[offset+4:rdEnd])
	return rdEnd, nil
}
