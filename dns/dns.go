// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// 该文件定义了 DNS 协议的主要消息结构。
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// DNS 消息结构定义在 RFC 1034 / RFC 1035 中
// +---------------------+
// |        Header       | // DNS 头部，包含查询ID，标志位，查询数量，回答数量，授权数量，附加数量等信息
// +---------------------+
// |       Question      | // DNS 查询部分，包含查询的域名和查询类型
// +---------------------+
// |        Answer       | // DNS 回答部分，包含查询的结果
// +---------------------+
// |      Authority      | // DNS 权威部分，包含授权的域名服务器
// +---------------------+
// |      Additional     | // DNS 附加部分，包含额外的信息
// +---------------------+

// DNS 表示 DNS协议 的消息结构。
type DNS struct {
	// DNS 消息头部
	Header DNSHeader // DNS 头部（Header）
	// DNS消息的各个部分（Section）
	Questions   []DNSQuestion       // DNS 查询部分（Questions Section）
	Answers     []DNSResourceRecord // DNS 回答部分（Answers Section）
	Authorities []DNSResourceRecord // DNS 权威部分（Authorities Section）
	Additionals []DNSResourceRecord // DNS 附加部分（Additonal Section）
}

//  DNS 头部 编码格式
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSHeader 表示DNS数据包的头部部分。
type DNSHeader struct {
	ID     uint16    // 查询ID
	QR     bool      // 查询/响应标志
	OpCode DNSOpCode // 查询操作码

	AA bool  // 权威回答标志（Authoritative Answer）
	TC bool  // 截断标志（Truncated）
	RD bool  // 递归查询标志（Recursion Desired）
	RA bool  // 递归可用标志（Recursion Available）
	Z  uint8 // 保留字段

	ResponseCode DNSResponseCode // 响应码
	QDCount      uint16          // 问题部分的条目数量
	ANCount      uint16          // 回答部分的资源记录数量
	NSCount      uint16          // 权威部分的资源记录数量
	ARCount      uint16          // 附加部分的资源记录数量
}

// DNSQuestion 表示DNS查询的问题部分。
type DNSQuestion struct {
	Name  string
	Type  DNSRRType
	Class DNSClass
}

//  DNS 资源记录 编码格式
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                                               |
//  /                                               /
//  /                      NAME                     /
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TYPE                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     CLASS                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TTL                      |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   RDLENGTH                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//  /                     RDATA                     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSResourceRecord 表示 DNS 资源记录。
type DNSResourceRecord struct {
	Name  string
	Type  DNSRRType
	Class DNSClass
	TTL   uint32
	RDLen uint16
	RData DNSRRRDATA
}

// Size 返回DNS层的*准确（也是实际上的）*大小
// 错误的字段值不会影响Size的计算。
func (d *DNS) Size() int {
	size := d.Header.Size()
	for _, question := range d.Questions {
		size += question.Size()
	}
	for _, answer := range d.Answers {
		size += answer.Size()
	}
	for _, authority := range d.Authorities {
		size += authority.Size()
	}
	for _, additional := range d.Additionals {
		size += additional.Size()
	}
	return size
}

func (d *DNS) String() string {
	return fmt.Sprint(
		"### DNS Message ###\n",
		d.Header,
		d.Questions,
		d.Answers,
		d.Authorities,
		d.Additionals,
		"### End of DNS Message ###\n",
	)
}

// Encode 将DNS层编码到字节切片中。
func (dns *DNS) Encode() []byte {
	bytesArray := make([]byte, dns.Size())
	// 编码头部
	offset, err := dns.Header.EncodeToBuffer(bytesArray)
	if err != nil {
		fmt.Println("DNS Encode Error:\n", err)
		os.Exit(1)
	}

	// 编码查询部分
	for _, question := range dns.Questions {
		increment, err := question.EncodeToBuffer(bytesArray[offset:])
		offset += increment
		if err != nil {
			fmt.Println("DNS Encode Error:\n", err)
			os.Exit(1)
		}
	}

	// 编码回答部分
	for _, answer := range dns.Answers {
		increment, err := answer.EncodeToBuffer(bytesArray[offset:])
		offset += increment
		if err != nil {
			fmt.Println("DNS Encode Error:\n", err)
			os.Exit(1)
		}
	}

	// 编码权威部分
	for _, authority := range dns.Authorities {
		increment, err := authority.EncodeToBuffer(bytesArray[offset:])
		offset += increment
		if err != nil {
			fmt.Println("DNS Encode Error:\n", err)
			os.Exit(1)
		}
	}

	// 编码附加部分
	for _, additional := range dns.Additionals {
		increment, err := additional.EncodeToBuffer(bytesArray[offset:])
		offset += increment
		if err != nil {
			fmt.Println("DNS Encode Error:\n", err)
			os.Exit(1)
		}
	}

	// 编码完成⚡
	return nil
}

// EncodeToBuffer 将DNS层编码到传入的缓冲区中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (dns *DNS) EncodeToBuffer(buffer []byte) (int, error) {
	// 编码头部
	offset, err := dns.Header.EncodeToBuffer(buffer)
	if err != nil {
		return -1, errors.New("DNS SerializeTo Error:\n" + err.Error())
	}

	// 编码查询部分
	for _, question := range dns.Questions {
		increment, err := question.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("DNS SerializeTo Error:\n" + err.Error())
		}
	}

	// 编码回答部分
	for _, answer := range dns.Answers {
		increment, err := answer.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("DNS SerializeTo Error:\n" + err.Error())
		}
	}

	// 编码权威部分
	for _, authority := range dns.Authorities {
		increment, err := authority.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("DNS SerializeTo Error:\n" + err.Error())
		}
	}

	// 编码附加部分
	for _, additional := range dns.Additionals {
		increment, err := additional.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("DNS SerializeTo Error:\n" + err.Error())
		}
	}

	// 编码完成⚡
	return offset, nil
}

// Size 返回DNS消息头部的大小。
// - 头部大小固定为12字节。
func (dns *DNSHeader) Size() int {
	return 12
}

// String 以“易读的形式”返回DNS消息头部的字符串表示。
func (dns *DNSHeader) String() string {
	return fmt.Sprint(
		"### DNS Header ###\n",
		"ID: ", dns.ID, "\n",
		"QR: ", dns.QR, "\n",
		"OpCode: ", dns.OpCode, "\n",
		"AA: ", dns.AA, "\n",
		"TC: ", dns.TC, "\n",
		"RD: ", dns.RD, "\n",
		"RA: ", dns.RA, "\n",
		"Z: ", dns.Z, "\n",
		"ResponseCode: ", dns.ResponseCode, "\n",
		"QDCount: ", dns.QDCount, "\n",
		"ANCount: ", dns.ANCount, "\n",
		"NSCount: ", dns.NSCount, "\n",
		"ARCount: ", dns.ARCount, "\n",
		"### End of DNS Header ###\n",
	)
}

// Encode 将DNS消息头部编码到字节切片中。
func (dns *DNSHeader) Encode() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer, dns.ID)
	flags := uint16(0)
	if dns.QR {
		flags |= 1 << 15
	}
	flags |= uint16(dns.OpCode) << 11
	if dns.AA {
		flags |= 1 << 10
	}
	if dns.TC {
		flags |= 1 << 9
	}
	if dns.RD {
		flags |= 1 << 8
	}
	if dns.RA {
		flags |= 1 << 7
	}
	flags |= uint16(dns.ResponseCode) & 0x0f
	binary.BigEndian.PutUint16(buffer[2:], flags)
	binary.BigEndian.PutUint16(buffer[4:], dns.QDCount)
	binary.BigEndian.PutUint16(buffer[6:], dns.ANCount)
	binary.BigEndian.PutUint16(buffer[8:], dns.NSCount)
	binary.BigEndian.PutUint16(buffer[10:], dns.ARCount)
	return buffer
}

// EncodeToBuffer 将DNS消息头部编码到传入的缓冲区中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (dns *DNSHeader) EncodeToBuffer(buffer []byte) (int, error) {
	binary.BigEndian.PutUint16(buffer, dns.ID)
	flags := uint16(0)
	if dns.QR {
		flags |= 1 << 15
	}
	flags |= uint16(dns.OpCode) << 11
	if dns.AA {
		flags |= 1 << 10
	}
	if dns.TC {
		flags |= 1 << 9
	}
	if dns.RD {
		flags |= 1 << 8
	}
	if dns.RA {
		flags |= 1 << 7
	}
	flags |= uint16(dns.ResponseCode) & 0x0f
	binary.BigEndian.PutUint16(buffer[2:], flags)
	binary.BigEndian.PutUint16(buffer[4:], dns.QDCount)
	binary.BigEndian.PutUint16(buffer[6:], dns.ANCount)
	binary.BigEndian.PutUint16(buffer[8:], dns.NSCount)
	binary.BigEndian.PutUint16(buffer[10:], dns.ARCount)
	return 12, nil
}

// Size 返回DNS查询的问题部分的大小。
func (dnsQuestion *DNSQuestion) Size() int {
	return GetNameWireLength(&dnsQuestion.Name) + 4
}

// String 以“易读的形式”返回DNS查询的问题部分的字符串表示。
func (dnsQuestion *DNSQuestion) String() string {
	return fmt.Sprint(
		"### DNS Question ###\n",
		"Name: ", dnsQuestion.Name, "\n",
		"Type: ", dnsQuestion.Type, "\n",
		"Class: ", dnsQuestion.Class, "\n",
		"### End of DNS Question ###\n",
	)
}

// Encode 将DNS查询的问题部分编码到字节切片中。
func (dnsQuestion *DNSQuestion) Encode() []byte {
	buffer := make([]byte, dnsQuestion.Size())
	_, _ = EncodeDomainNameToBuffer(&dnsQuestion.Name, buffer)
	binary.BigEndian.PutUint16(buffer[len(buffer)-4:], uint16(dnsQuestion.Type))
	binary.BigEndian.PutUint16(buffer[len(buffer)-2:], uint16(dnsQuestion.Class))
	return buffer
}

// EncodeToBuffer 将DNS查询的问题部分编码到传入的缓冲区中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (dnsQuestion *DNSQuestion) EncodeToBuffer(buffer []byte) (int, error) {
	_, err := EncodeDomainNameToBuffer(&dnsQuestion.Name, buffer)
	if err != nil {
		return -1, err
	}
	dqSize := dnsQuestion.Size()
	binary.BigEndian.PutUint16(buffer[dqSize-4:], uint16(dnsQuestion.Type))
	binary.BigEndian.PutUint16(buffer[dqSize-2:], uint16(dnsQuestion.Class))
	return dqSize, nil
}
