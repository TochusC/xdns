// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// rdata.go 文件定义了用于表示 DNS 资源记录 RDATA 的接口 DNSRRRDATA。
package dns

import (
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
}

// NS RDATA 编码格式
type DNSNSRecordRDATA struct {
	NS string
}

func (rdata *DNSNSRecordRDATA) Type() DNSType {
	return DNSRRTypeNS
}

func (rdata *DNSNSRecordRDATA) Size() int {
	return GetNameWireLength(&rdata.NS)
}

func (rdata *DNSNSRecordRDATA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"NS: ", rdata.NS, "\n",
		"### End of RDATA Section ###",
	)
}

func (rdata *DNSNSRecordRDATA) Encode() []byte {
	bytesArray := make([]byte, rdata.Size())
	_, err := EncodeDomainNameToBuffer(&rdata.NS, bytesArray)
	if err != nil {
		fmt.Println("EncodeDomainNameToBuffer failed: ", err)
		os.Exit(1)
	}
	return bytesArray
}

func (rdata *DNSNSRecordRDATA) EncodeToBuffer(buffer []byte) (int, error) {
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
