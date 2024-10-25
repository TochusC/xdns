// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// 该文件定义了用于表示 DNS 资源记录 RDATA 部分的接口。
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
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
// 为了实现RDATA的灵活性，我们定义了 DNSRRRDATA 接口,
// 任何实现了 DNSRRRDATA 接口的类型都可以作为 DNS 资源记录的 RDATA 部分。
type DNSRRRDATA interface {
	// Type 方法返回 RDATA 部分的类型。
	//  - 其返回值为 DNSRRType。
	// 许多对象（如 DNS 结构体） 与 DNSRRRDATA接口 都有着Size、String、Encode...等方法，
	// 但 DNS 结构体没有 Type 方法，而是直接定义了 DNSRRType 类型的 Type 字段 。
	// Type 方法特化了 DNSRRRDATA 接口使得 DNS 结构体等对象不是 DNSRRRDATA 接口的实现。
	Type() DNSRRType

	// Size 方法返回 RDATA 部分的大小。
	//  - 其返回值为 RDATA 部分的*准确*大小。
	Size() int

	// String 方法以*易读的形式*返回对应 资源记录 RDATA 部分的 字符串表示。
	//  - 其返回值为 RDATA 部分的字符串表示。
	String() string

	/* TODO: Mais 等到真正需要时再实现吧？

	// StringRFC 方法以*RFC文档规定的ASCII表示*返回对应 资源记录 RDATA 部分的 字符串表示。
	//  - 其返回值为 RDATA 部分的字符串表示。
	StringRFC() string

	// Encode 方法返回编码后的 RDATA 部分。
	//  - 其返回值为 编码后的字节切片。
	Encode() []byte

	*/

	// EncodeToBuffer 方法将编码后的 RDATA 部分写入缓冲区。
	//  - 其接收 缓冲区切片 作为参数。
	//  - 返回值为 写入的字节数 和 错误信息。
	EncodeToBuffer(buffer []byte) (int, error)
}

// Size 返回 DNS 资源记录的*准确*大小。
//   - RDLength 字段可由用户自行设置一个错误的值。
func (rr *DNSResourceRecord) Size() int {
	return GetNameWireLength(&rr.Name) + 10 + rr.RData.Size()
}

// String 以*易读的形式*返回 DNS 资源记录的字符串表示。
//   - 其返回值为 DNS 资源记录的字符串表示。
func (rr *DNSResourceRecord) String() string {
	return fmt.Sprint(
		"### DNS Resource Record ###\n",
		"Name:", rr.Name, "\n",
		"Type:", rr.Type, "\n",
		"Class:", rr.Class, "\n",
		"TTL:", rr.TTL, "\n",
		"RDLen:", rr.RDLen, "\n",
		"RData:", rr.RData.String(), "\n",
		"### End of DNS Resource Record ###\n",
	)
}

// Encode 方法编码 DNS 资源记录至返回的字节切片中。
// - 其返回值为 编码后的字节切片 。
func (rr *DNSResourceRecord) Encode() []byte {
	byteArray := make([]byte, rr.Size())
	offset, err := EncodeDomainNameToBuffer(&rr.Name, byteArray)
	if err != nil {
		fmt.Println("DNSResourceRecord Encode Error:\n", err)
		os.Exit(1)
	}
	binary.BigEndian.PutUint16(byteArray[offset:], uint16(rr.Type))
	binary.BigEndian.PutUint16(byteArray[offset+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(byteArray[offset+4:], rr.TTL)
	binary.BigEndian.PutUint16(byteArray[offset+8:], rr.RDLen)
	_, err = rr.RData.EncodeToBuffer(byteArray[offset+10:])
	if err != nil {
		fmt.Println("DNSResourceRecord Encode Error:\n", err)
		os.Exit(1)
	}
	return byteArray
}

// EncodeToBuffer 将编码 DNS 资源记录至传入的缓冲区中。
//   - 其接收两个参数：缓冲区 和 偏移量。
//   - 返回值为 写入字节数 和 错误信息。
//
// 如果出现错误，返回 -1 和 相应报错。
func (rr *DNSResourceRecord) EncodeToBuffer(buffer []byte) (int, error) {
	_, err := EncodeDomainNameToBuffer(&rr.Name, buffer)
	if err != nil {
		return -1, err
	}
	binary.BigEndian.PutUint16(buffer, uint16(rr.Type))
	binary.BigEndian.PutUint16(buffer[2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(buffer[4:], rr.TTL)
	binary.BigEndian.PutUint16(buffer[8:], rr.RDLen)

	rdLen, err := rr.RData.EncodeToBuffer(buffer[10:])
	if err != nil {
		err = errors.New("DNSResourceRecord EncodeToBuffer Error:\n" + err.Error())
		return -1, err
	}
	return 10 + rdLen, err
}
