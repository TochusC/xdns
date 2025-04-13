// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// dns.go 文件定义了 DNS 协议的主要消息结构。
// DNS消息结构定义在 RFC 1034 / RFC 1035 中。
// 最顶层的结构是 DNSMessage，其包含了 DNSHeader, DNSQuestionSection, ResponseSection 等部分。

package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DNS消息结构定义在 RFC 1034 / RFC 1035 中
// +---------------------+
// |        Header       | // DNS消息 头部，包含查询ID，标志位，查询数量，回答数量，授权数量，附加数量等信息
// +---------------------+
// |       Question      | // DNS消息 查询部分，包含查询的域名和查询类型
// +---------------------+
// |        Answer       | // DNS消息 回答部分，包含查询的结果
// +---------------------+
// |      Authority      | // DNS消息 权威部分，包含授权的域名服务器
// +---------------------+
// |      Additional     | // DNS消息 附加部分，包含额外的信息
// +---------------------+

// DNSMessage 表示 DNS协议 的消息结构。
type DNSMessage struct {
	// DNS消息 头部
	Header DNSHeader // DNS 头部（Header）
	// DNS消息的各个部分（Section）
	Question   DNSQuestionSection // DNS 查询部分（Questions Section）
	Answer     DNSResponseSection // DNS 回答部分（Answers Section）
	Authority  DNSResponseSection // DNS 权威部分（Authority Section）
	Additional DNSResponseSection // DNS 附加部分（Additional Section）
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
	ID uint16 // 查询ID
	// QR 查询/响应标志
	QR     bool      // 0: 查询 1: 响应
	OpCode DNSOpCode // 查询操作码

	AA bool  // 权威回答标志（Authoritative Answer）
	TC bool  // 截断标志（Truncated）
	RD bool  // 递归查询标志（Recursion Desired）
	RA bool  // 递归可用标志（Recursion Available）
	Z  uint8 // 保留字段

	RCode   DNSResponseCode // 响应码
	QDCount uint16          // 问题部分的条目数量
	ANCount uint16          // 回答部分的资源记录数量
	NSCount uint16          // 权威部分的资源记录数量
	ARCount uint16          // 附加部分的资源记录数量
}

// DNS 问题 编码格式
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

// DNSQuestionSection 表示DNS消息的 问题部分
type DNSQuestionSection []DNSQuestion

// DNSQuestion 表示DNS查询的问题记录
type DNSQuestion struct {
	Name  string
	Type  DNSType
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

// DNSResponseSection 表示DNS响应的资源记录部分
type DNSResponseSection []DNSResourceRecord

// DNSResourceRecord 表示 DNS 资源记录。
// 设置RDLen为0时，将根据RData的实际大小进行编码。
type DNSResourceRecord struct {
	Name  string
	Type  DNSType
	Class DNSClass
	TTL   uint32
	RDLen uint16
	RData DNSRRRDATA
}

// DNSMessage 相关方法定义

// Size 返回DNSMessage的*准确（也是实际上的）*大小
// 错误的字段值不会影响Size的计算。
func (dnsMessage *DNSMessage) Size() int {
	size := dnsMessage.Header.Size()
	for _, question := range dnsMessage.Question {
		size += question.Size()
	}
	for _, answer := range dnsMessage.Answer {
		size += answer.Size()
	}
	for _, authority := range dnsMessage.Authority {
		size += authority.Size()
	}
	for _, additional := range dnsMessage.Additional {
		size += additional.Size()
	}
	return size
}

func (dnsMessage *DNSMessage) String() string {
	return fmt.Sprint(
		"### DNS Message ###\n",
		dnsMessage.Header.String(), "\n",
		dnsMessage.Question.String(),
		dnsMessage.Answer.String(),
		dnsMessage.Authority.String(),
		dnsMessage.Additional.String(),
		"### DNS Message End ###",
	)
}

// Equal 检查两个DNS消息是否相等。
func (dnsMessage *DNSMessage) Equal(other *DNSMessage) bool {
	if dnsMessage.Header != other.Header {
		return false
	}
	if len(dnsMessage.Question) != len(other.Question) {
		return false
	}
	for i, question := range dnsMessage.Question {
		if question != other.Question[i] {
			return false
		}
	}
	if len(dnsMessage.Answer) != len(other.Answer) {
		return false
	}
	for i, answer := range dnsMessage.Answer {
		if answer != other.Answer[i] {
			return false
		}
	}
	if len(dnsMessage.Authority) != len(other.Authority) {
		return false
	}
	for i, authority := range dnsMessage.Authority {
		if authority != other.Authority[i] {
			return false
		}
	}
	if len(dnsMessage.Additional) != len(other.Additional) {
		return false
	}
	for i, additional := range dnsMessage.Additional {
		if additional != other.Additional[i] {
			return false
		}
	}
	return true
}

// Encode 将DNSMessage编码到字节切片中。
func (dnsMessage *DNSMessage) Encode() []byte {
	bytesArray := make([]byte, dnsMessage.Size())
	// 编码头部
	offset, err := dnsMessage.Header.EncodeToBuffer(bytesArray)
	if err != nil {
		panic(fmt.Sprintln("method DNSMessage Encode error(Header):\n", err))
	}

	// 编码查询部分
	increment, err := dnsMessage.Question.EncodeToBuffer(bytesArray[offset:])
	offset += increment
	if err != nil {
		panic(fmt.Sprintln("method DNSMessage Encode error(Question Section):\n", err))
	}
	// 编码回答部分
	increment, err = dnsMessage.Answer.EncodeToBuffer(bytesArray[offset:])
	offset += increment
	if err != nil {
		panic(fmt.Sprintln("method DNSMessage Encode error(Answer Section):\n", err))
	}

	// 编码权威部分
	increment, err = dnsMessage.Authority.EncodeToBuffer(bytesArray[offset:])
	offset += increment
	if err != nil {
		panic(fmt.Sprintln("method DNSMessage Encode error(Authority Section):\n", err))
	}

	// 编码附加部分
	increment, err = dnsMessage.Additional.EncodeToBuffer(bytesArray[offset:])
	offset += increment
	if err != nil {
		panic(fmt.Sprintln("method DNSMessage Encode error(Additional Section):\n", err))
	}

	// 编码完成⚡
	return bytesArray
}

// EncodeToBuffer 将DNS消息编码到传入的缓冲区中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (dnsMessage *DNSMessage) EncodeToBuffer(buffer []byte) (int, error) {
	// 编码头部
	offset, err := dnsMessage.Header.EncodeToBuffer(buffer)
	if err != nil {
		return -1, errors.New("method DNSMessage EncodeToBuffer error: encode Header failed.\n" + err.Error())
	}

	// 编码查询部分
	for _, question := range dnsMessage.Question {
		increment, err := question.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("method DNSMessage EncodeToBuffer failed: encode Question failed.\n" + err.Error())
		}
	}

	// 编码回答部分
	for _, answer := range dnsMessage.Answer {
		increment, err := answer.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("method DNSMessage EncodeToBuffer failed: encode Answer failed.\n" + err.Error())
		}
	}

	// 编码权威部分
	for _, authority := range dnsMessage.Authority {
		increment, err := authority.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("method DNSMessage EncodeToBuffer error: encode Authority failed.\n" + err.Error())
		}
	}

	// 编码附加部分
	for _, additional := range dnsMessage.Additional {
		increment, err := additional.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, errors.New("method DNSMessage EncodeToBuffer failed: encode Additonal failed.\n" + err.Error())
		}
	}

	// 编码完成⚡
	return offset, nil
}

func (dnsMessage *DNSMessage) DecodeFromBuffer(buffer []byte, offset int) (int, error) {
	// 解码头部
	offset, err := dnsMessage.Header.DecodeFromBuffer(buffer, offset)
	if err != nil {
		return -1, err
	}

	// 根据头部字段 初始化 DNSMessage 的各个部分
	dnsMessage.Question = make(DNSQuestionSection, dnsMessage.Header.QDCount)
	dnsMessage.Answer = make(DNSResponseSection, dnsMessage.Header.ANCount)
	dnsMessage.Authority = make(DNSResponseSection, dnsMessage.Header.NSCount)
	dnsMessage.Additional = make(DNSResponseSection, dnsMessage.Header.ARCount)

	// 解码查询部分
	for i := 0; i < int(dnsMessage.Header.QDCount); i++ {
		offset, err = dnsMessage.Question[i].DecodeFromBuffer(buffer, offset)
		if err != nil {
			return -1, fmt.Errorf("method DNS Decode error: decode Question#%d, Offset:%d, failed:\n%s", i, offset, err)
		}
	}

	// 解码回答部分
	for i := 0; i < int(dnsMessage.Header.ANCount); i++ {
		offset, err = dnsMessage.Answer[i].DecodeFromBuffer(buffer, offset)
		if err != nil {
			return -1, fmt.Errorf("method DNS Decode error: decode Answer#%d, Offset:%d, failed:\n%s", i, offset, err)
		}
	}

	// 解码权威部分
	for i := 0; i < int(dnsMessage.Header.NSCount); i++ {
		offset, err = dnsMessage.Authority[i].DecodeFromBuffer(buffer, offset)
		if err != nil {
			return -1, fmt.Errorf("method DNS Decode error: decode Authority#%d, Offset:%d, failed:\n%s", i, offset, err)
		}
	}

	// 解码附加部分
	for i := 0; i < int(dnsMessage.Header.ARCount); i++ {
		offset, err = dnsMessage.Additional[i].DecodeFromBuffer(buffer, offset)
		if err != nil {
			return -1, fmt.Errorf("method DNS Decode error: decode Additional#%d, Offset:%d, failed:\n%s", i, offset, err)
		}
	}

	// 解码完成⚡
	return offset, nil
}

// DNSHeader 相关方法定义

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
		"RCode: ", dns.RCode, "\n",
		"QDCount: ", dns.QDCount, "\n",
		"ANCount: ", dns.ANCount, "\n",
		"NSCount: ", dns.NSCount, "\n",
		"ARCount: ", dns.ARCount,
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
	flags |= uint16(dns.RCode) & 0x0f
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
	if len(buffer) < 12 {
		return -1, fmt.Errorf("buffer length %d is less than DNSHeader size 12", len(buffer))
	}
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
	flags |= uint16(dns.RCode) & 0x0f
	binary.BigEndian.PutUint16(buffer[2:], flags)
	binary.BigEndian.PutUint16(buffer[4:], dns.QDCount)
	binary.BigEndian.PutUint16(buffer[6:], dns.ANCount)
	binary.BigEndian.PutUint16(buffer[8:], dns.NSCount)
	binary.BigEndian.PutUint16(buffer[10:], dns.ARCount)
	return 12, nil
}

// DecodeFromBuffer 从存储有 DNS消息 的缓冲区中解码DNS消息头部。
//   - 其接收参数：缓冲区 和 偏移量。
//   - 返回值为 解码后偏移量 和 错误信息。
//
// 如果出现错误，返回 -1 和 相应报错。
func (dnsHeader *DNSHeader) DecodeFromBuffer(buffer []byte, offset int) (int, error) {
	// 检查缓冲区长度
	if len(buffer) < offset+12 {
		return -1, fmt.Errorf("method DNSHeader DecodeFromBuffer failed: buffer length %d is less than DNSHeader size 12", len(buffer))
	}
	// 开始解码
	dnsHeader.ID = binary.BigEndian.Uint16(buffer[offset:])
	flags := binary.BigEndian.Uint16(buffer[offset+2:])
	dnsHeader.QR = flags>>15 == 1
	dnsHeader.OpCode = DNSOpCode((flags >> 11) & 0x0f)
	dnsHeader.AA = flags>>10&1 == 1
	dnsHeader.TC = flags>>9&1 == 1
	dnsHeader.RD = flags>>8&1 == 1
	dnsHeader.RA = flags>>7&1 == 1
	dnsHeader.Z = uint8((flags >> 4) & 0x07)
	dnsHeader.RCode = DNSResponseCode(flags & 0x0f)
	dnsHeader.QDCount = binary.BigEndian.Uint16(buffer[offset+4:])
	dnsHeader.ANCount = binary.BigEndian.Uint16(buffer[offset+6:])
	dnsHeader.NSCount = binary.BigEndian.Uint16(buffer[offset+8:])
	dnsHeader.ARCount = binary.BigEndian.Uint16(buffer[offset+10:])

	return offset + 12, nil
}

// DNSQuestion 相关方法定义

// Size 返回DNS消息 的 问题部分的大小。
func (dnsQuestion *DNSQuestion) Size() int {
	return GetDomainNameWireLen(&dnsQuestion.Name) + 4
}

// String 以“易读的形式”返回DNS消息 的 问题部分的字符串表示。
func (dnsQuestion *DNSQuestion) String() string {
	return fmt.Sprint(
		"### DNS Question ###\n",
		"Name: ", dnsQuestion.Name, "\n",
		"Type: ", dnsQuestion.Type, "\n",
		"Class: ", dnsQuestion.Class,
	)
}

// Size 返回DNS消息 的 问题部分的大小。
func (section DNSQuestionSection) Size() int {
	size := 0
	for _, question := range section {
		size += question.Size()
	}
	return size
}

// String 以“易读的形式”返回DNS消息 的 问题部分的字符串表示。
// - 其返回值为 DNS消息 的 问题部分的字符串表示。
func (section DNSQuestionSection) String() string {
	var result string
	for _, question := range section {
		result += question.String() + "\n"
	}
	return result
}

// Equal 检查两个DNS消息的问题部分是否相等。
// - 其接收参数：另一个DNS消息的问题部分
// - 返回值为 两个DNS消息的问题部分是否相等。
func (section DNSQuestionSection) Equal(other DNSQuestionSection) bool {
	if len(section) != len(other) {
		return false
	}
	for i, question := range section {
		if question != other[i] {
			return false
		}
	}
	return true
}

// Encode 将DNS消息 的 问题部分编码到字节切片中。
// - 其返回值为 编码后的字节切片。
func (section DNSQuestionSection) Encode() []byte {
	bytesArray := make([]byte, section.Size())
	offset := 0
	for qid, question := range section {
		increment, err := question.EncodeToBuffer(bytesArray[offset:])
		offset += increment
		if err != nil {
			panic(fmt.Sprintf("method DNSQuestionSection Encode failed: encode Question#%d failed:\n%s", qid, err))
		}
	}
	return bytesArray
}

// EncodeToBuffer 将DNS消息 的 问题部分编码到传入的缓冲区中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (section DNSQuestionSection) EncodeToBuffer(buffer []byte) (int, error) {
	offset := 0
	for qid, question := range section {
		increment, err := question.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, fmt.Errorf("method DNSQuestionSection EncodeToBuffer failed: encode Question#%d failed:\n%s", qid, err)
		}
	}
	return offset, nil
}

// DecodeFromBuffer 从存储有 DNS消息 的缓冲区中解码DNS消息的 问题部分 。
// - 其接收参数：缓冲区 和 偏移量。
// - 返回值为 解码后偏移量 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (dnsQuestion *DNSQuestion) DecodeFromBuffer(buffer []byte, offset int) (int, error) {
	var err error
	// 解码域名
	dnsQuestion.Name, offset, err = DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, fmt.Errorf("method DNSQuestion DecodeFromBuffer failed: decode Name failed.\n%s", err)
	}
	// 解码类型
	dnsQuestion.Type = DNSType(binary.BigEndian.Uint16(buffer[offset:]))
	// 解码类
	dnsQuestion.Class = DNSClass(binary.BigEndian.Uint16(buffer[offset+2:]))
	return offset + 4, nil
}

// Encode 将 DNS消息的问题部分 编码到 字节切片 中。
func (dnsQuestion *DNSQuestion) Encode() []byte {
	buffer := make([]byte, dnsQuestion.Size())
	offset, err := EncodeDomainNameToBuffer(&dnsQuestion.Name, buffer)
	if err != nil {
		panic(fmt.Sprintf("method DNSQuestion Encode failed: encode Question name failed\n%s\n", err))
	}
	binary.BigEndian.PutUint16(buffer[offset:], uint16(dnsQuestion.Type))
	binary.BigEndian.PutUint16(buffer[offset+2:], uint16(dnsQuestion.Class))
	return buffer
}

// EncodeToBuffer 将D NS消息的问题部分 编码到 传入的缓冲区 中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (dnsQuestion *DNSQuestion) EncodeToBuffer(buffer []byte) (int, error) {
	dqSize := dnsQuestion.Size()
	if len(buffer) < dqSize {
		return -1, fmt.Errorf("EncodeToBuffer failed: buffer length %d is less than DNSQuestion size %d", len(buffer), dqSize)
	}
	_, err := EncodeDomainNameToBuffer(&dnsQuestion.Name, buffer)
	if err != nil {
		return -1, err
	}
	binary.BigEndian.PutUint16(buffer[dqSize-4:], uint16(dnsQuestion.Type))
	binary.BigEndian.PutUint16(buffer[dqSize-2:], uint16(dnsQuestion.Class))
	return dqSize, nil
}

// Size 返回DNS响应部分的大小。
func (responseSection DNSResponseSection) Size() int {
	size := 0
	for _, record := range responseSection {
		size += record.Size()
	}
	return size
}

// String 以“易读的形式”返回DNS响应部分的字符串表示。
func (responseSection DNSResponseSection) String() string {
	var result string
	for _, record := range responseSection {
		result += record.String() + "\n"
	}
	return result
}

// Equal 检查两个DNS响应部分是否相等。
func (responseSection DNSResponseSection) Equal(other DNSResponseSection) bool {
	if len(responseSection) != len(other) {
		return false
	}
	for i, record := range responseSection {
		if record != other[i] {
			return false
		}
	}
	return true
}

// Encode 将 DNS响应部分 编码到 字节切片 中。
// - 其返回值为 编码后的字节切片。
func (responseSection DNSResponseSection) Encode() []byte {
	bytesArray := make([]byte, responseSection.Size())
	offset := 0
	for _, record := range responseSection {
		increment, err := record.EncodeToBuffer(bytesArray[offset:])
		offset += increment
		if err != nil {
			panic(fmt.Sprintf("method DNSResponseSection Encode failed: encode Record failed:\n%s\n", err))
		}
	}
	return bytesArray
}

// EncodeToBuffer 将DNS响应部分编码到传入的缓冲区中。
// - 其接收参数：缓冲区
// - 返回值为 写入字节数 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (responseSection DNSResponseSection) EncodeToBuffer(buffer []byte) (int, error) {
	offset := 0
	for _, record := range responseSection {
		increment, err := record.EncodeToBuffer(buffer[offset:])
		offset += increment
		if err != nil {
			return -1, err
		}
	}
	return offset, nil
}

// DecodeFromBuffer 从存储有 DNS消息 的缓冲区中解码DNS消息的 响应部分 。
// - 其接收参数：缓冲区 和 偏移量。
// - 返回值为 解码后的DNSResponseSection,  解码后偏移量, 错误信息。
// 如果出现错误，返回nil, -1 和 相应报错。
// DNSResponseSection 为 DNSResourceRecord 数组的切片
// 返回DNSResponseSection不会影响程序的性能，因为切片是引用传递。
func (responseSection DNSResponseSection) DecodeFromBuffer(buffer []byte, offset int) (int, error) {
	var err error
	for i := 0; i < len(responseSection); i++ {
		responseSection = append(responseSection, DNSResourceRecord{})
		offset, err = responseSection[i].DecodeFromBuffer(buffer, offset)
		if err != nil {
			return -1, err
		}
	}
	return offset, nil
}

// Size 返回 DNS 资源记录的*准确*大小。
//   - RDLength 字段可由用户自行设置一个错误的值。
func (rr *DNSResourceRecord) Size() int {
	return GetDomainNameWireLen(&rr.Name) + 10 + rr.RData.Size()
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
		"RData:\n", rr.RData.String(),
	)
}

// Encode 方法编码 DNS 资源记录至返回的字节切片中。
// - 其返回值为 编码后的字节切片 。
func (rr *DNSResourceRecord) Encode() []byte {
	byteArray := make([]byte, rr.Size())
	offset, err := EncodeDomainNameToBuffer(&rr.Name, byteArray)
	if err != nil {
		panic(fmt.Sprintf("method DNSResourceRecord Encode failed: encode Name failed\n%s\n", err))
	}
	binary.BigEndian.PutUint16(byteArray[offset:], uint16(rr.Type))
	binary.BigEndian.PutUint16(byteArray[offset+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(byteArray[offset+4:], rr.TTL)
	rdLen, err := rr.RData.EncodeToBuffer(byteArray[offset+10:])
	if err != nil {
		panic(fmt.Sprintf("method DNSResourceRecord Encode failed: encode RDATA failed\n%s\n", err))
	}
	if rr.RDLen == 0 {
		binary.BigEndian.PutUint16(byteArray[offset+8:], uint16(rdLen))
	} else {
		binary.BigEndian.PutUint16(byteArray[offset+8:], rr.RDLen)
	}
	return byteArray
}

// EncodeToBuffer 将编码 DNS 资源记录至传入的缓冲区中。
//   - 其接收两个参数：缓冲区 和 偏移量。
//   - 返回值为 写入字节数 和 错误信息。
//
// 如果出现错误，返回 -1 和 相应报错。
func (rr *DNSResourceRecord) EncodeToBuffer(buffer []byte) (int, error) {
	offset, err := EncodeDomainNameToBuffer(&rr.Name, buffer)
	if err != nil {
		return -1, err
	}
	binary.BigEndian.PutUint16(buffer[offset:], uint16(rr.Type))
	binary.BigEndian.PutUint16(buffer[offset+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(buffer[offset+4:], rr.TTL)
	rdLen, err := rr.RData.EncodeToBuffer(buffer[offset+10:])
	if rr.RDLen == 0 {
		binary.BigEndian.PutUint16(buffer[offset+8:], uint16(rdLen))
	} else {
		binary.BigEndian.PutUint16(buffer[offset+8:], rr.RDLen)
	}

	if err != nil {
		err = errors.New("DNSResourceRecord EncodeToBuffer error:\n" + err.Error())
		return -1, err
	}
	return offset + 10 + rdLen, err
}

// DecodeFromBuffer 从存储有 DNS消息 的缓冲区中解码DNS消息的 资源记录部分 。
// - 其接收参数：缓冲区 和 偏移量。
// - 返回值为 解码后偏移量 和 错误信息。
// 如果出现错误，返回 -1 和 相应报错。
func (rr *DNSResourceRecord) DecodeFromBuffer(buffer []byte, offset int) (int, error) {
	var err error
	// 解码域名
	name, offset, err := DecodeDomainNameFromBuffer(buffer, offset)
	if err != nil {
		return -1, err
	}
	rr.Name = name
	// 解码类型
	rr.Type = DNSType(binary.BigEndian.Uint16(buffer[offset:]))
	// 解码类
	rr.Class = DNSClass(binary.BigEndian.Uint16(buffer[offset+2:]))
	// 解码TTL
	rr.TTL = binary.BigEndian.Uint32(buffer[offset+4:])
	// 解码RDLen
	rr.RDLen = binary.BigEndian.Uint16(buffer[offset+8:])
	// 根据类型初始化 RData
	rr.RData = DNSRRRDATAFactory(rr.Type)
	// 解码RData
	offset, err = rr.RData.DecodeFromBuffer(buffer, offset+10, int(rr.RDLen))
	if err != nil {
		return -1, err
	}
	return offset, nil
}
