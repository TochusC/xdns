// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// standard.go 文件定义了 DNS 所使用到的一些标准化函数
// 其目前包括 <domain-name>, <character-string> 的编解码函数。
// 关于 <domain-name> 及 <character-string> 的详细定义
// 请参阅 RFC 1035 3.3节 Standard RRs。
//
// # <domain-name>
//
// 对于 <domain-name> 的编码，可接受 绝对域名 及 相对域名，
// 绝对域名 以 '.' 结尾，相对域名后不以'.'结尾。
// 传入的 相对域名 会视作为 绝对域名 进行编码。
//
// 而 <domain-name> 的解码则均以 相对域名 的形式返回结果。
// 当域名为 根域名 时，返回"."。
//
// [ RFC 1035 ] 规定了 DNS 域名的相关定义。
// DNS 域名由一系列标签组成，标签之间以'.'分隔。
// DNS 域名可分为绝对域名和相对域名，绝对域名以'.'结尾，而相对域名不以'.'结尾。
// DNS 域名的编码格式为：每个标签的长度 + 标签内容 + 0x00。
//
// DNS 域名存在压缩格式，即使用 指针 指向位于 DNS消息 其他位置的域名。
// 指针占据两个字节，高两位为 11，低14位为指向的位置，其格式形如：
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// | 1 1 |                 OFFSET                  |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 域名的压缩格式使得 DNS消息 中的域名表示存在以下 3 种形式：
//
//   - 以0x00字节结尾的标签序列；
//
//   - 一个指针；
//
//   - 以指针结尾的标签序列。
//
// 详细内容请参阅 RFC 1035 4.1.4. Message compression
//
// # <character-string>
//
// [ RFC 1035 ] 规定了 DNS 字符串的相关定义。
// DNS 字符串是一系列字符的序列，其编码格式为：字符串长度 + 字符串内容。
// 字符串长度为一个字节，表示字符串的长度，字符串内容为字符串的实际内容。
// 长度字节为0时，表示空字符串，长度最大为255，即 DNS 字符串最大长度为255。

package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// GetDomainNameWireLen 返回域名的 编码格式长度。
//   - 其接收参数为 域名字符串 的指针，
//   - 返回值为域名的 编码格式长度。
//
// 可以接收绝对域名及相对域名，所有域名均以绝对域名的长度计算。
func GetDomainNameWireLen(name *string) int {
	nameLength := len(*name)
	if (*name)[nameLength-1] == '.' {
		// 根域名
		if nameLength == 1 {
			return 1
		}
		return nameLength + 1
	}
	return nameLength + 2
}

// GetUpperDomainName 返回域名的上级域名。
//   - 其接收参数为 域名字符串 的指针，
//   - 返回值为域名的上级域名。
//
// 如果传入域名为根域名(TLD)，则返回根域名本身。
func GetUpperDomainName(name *string) string {
	if (*name)[0] == '.' {
		return *name
	}
	return (*name)[strings.Index(*name, ".")+1:]
}

// SplitDomainName 分割域名，其接受域名字符串，并返回分割后的字符串切片。
// 若域名为根域名，则返回长度为0的字符串切片。
func SplitDomainName(name *string) []string {
	if (*name)[0] == '.' {
		return []string{}
	}
	return strings.Split(*name, ".")
}

// EncodeDomainName 编码域名，其接受字符串，并返回编码后的字节切片。
// 可以接收绝对域名及相对域名，生成的域名都会以'.'(0x00)结尾。
func EncodeDomainName(name *string) []byte {
	encodedLen := GetDomainNameWireLen(name)
	byteArray := make([]byte, encodedLen)

	// 根域名，返回0x00
	if encodedLen == 1 {
		byteArray[0] = 0x00
		return byteArray
	}

	labelLength := 0
	for index := range *name {
		if (*name)[index] == '.' {
			byteArray[index-labelLength] = byte(labelLength)
			copy(byteArray[index-labelLength+1:], (*name)[index-labelLength:index])
			labelLength = 0
		} else {
			labelLength++
		}
	}
	if labelLength != 0 {
		byteArray[encodedLen-labelLength-2] = byte(labelLength)
		copy(byteArray[encodedLen-labelLength-1:], (*name)[len(*name)-labelLength:])
	}
	return byteArray
}

// EncodeDomainNameToBuffer 将域名编码到字节切片中。
//   - 其接收参数为 域名字符串 和 字节切片，
//   - 返回值为 编码后长度 及 报错信息。
//
// 如果出现错误，返回 -1, 及 相应报错 。
func EncodeDomainNameToBuffer(name *string, buffer []byte) (int, error) {
	encodedLen := GetDomainNameWireLen(name)
	if len(buffer) < encodedLen {
		return -1, fmt.Errorf(
			"EncodeDomainNameToBuffer Error: buffer is too small, require %d byte size, but got %d",
			encodedLen, len(buffer))
	}

	if encodedLen == 1 {
		buffer[0] = 0x00
		return 1, nil
	}

	labelLength := 0
	for index := range *name {
		if (*name)[index] == '.' {
			buffer[index-labelLength] = byte(labelLength)
			copy(buffer[index-labelLength+1:], (*name)[index-labelLength:index])
			labelLength = 0
		} else {
			labelLength++
		}
	}
	if labelLength != 0 {
		buffer[encodedLen-labelLength-2] = byte(labelLength)
		copy(buffer[encodedLen-labelLength-1:], (*name)[len(*name)-labelLength:])
	}
	return encodedLen, nil
}

const (
	NamePointerFlag = 0xC0
)

// DecodeDomainName 解码域名，其接受字节切片，并返回解码后域名。
// 返回的域名为*相对域名*，即不以'.'结尾。
// 若域名为根域名，则返回"."
func DecodeDomainName(data []byte) string {
	var name string
	nameLength := 0
	for ; data[nameLength] != 0x00; nameLength++ {
		labelLength := int(data[nameLength])
		name += string(data[nameLength+1:nameLength+1+labelLength]) + "."
		nameLength += labelLength
	}
	// 去掉最后的'.'
	if nameLength != 0 {
		return name[:len(name)-1]
	} else {
		return "."
	}
}

// DecodeDomainNameFromDNSBuffer 从 DNS 报文中解码域名。
//   - 其接收参数为 DNS 报文 和 域名的偏移量，
//   - 返回值为 解码后的域名, 解码后的偏移量 及 报错信息。
//
// 如果出现错误，返回空字符串，-1 及 相应报错 。
func DecodeDomainNameFromBuffer(data []byte, offset int) (string, int, error) {
	name := make([]byte, 0, 32)
	nameLength := 0
	dataLength := len(data)

	if dataLength < offset+1 {
		return "", -1, fmt.Errorf(
			"function DecodeDomainNameFromBuffer error:\nbuffer is too small, require %d byte size, but got %d",
			offset+1, dataLength)
	}

	for ; data[offset+nameLength] != 0x00; nameLength++ {
		labelLength := int(data[offset+nameLength])
		if labelLength >= 0xC0 {
			// 指针指向其他位置
			pointer := int(data[offset+nameLength])<<8 + int(data[offset+nameLength+1])
			pointer &= 0x3FFF
			decodedName, _, err := DecodeDomainNameFromBuffer(data, pointer)
			if err != nil {
				return "", -1, err
			}
			name = append(name, []byte(decodedName)...)
			return string(name), offset + nameLength + 2, nil
		}

		if dataLength < offset+nameLength+labelLength+1 {
			return "", -1, fmt.Errorf(
				"function DecodeDomainNameFromBuffer failed:\nbuffer is too small, require %d byte size, but got %d",
				offset+nameLength+1+labelLength, dataLength)
		}

		name = append(name, data[offset+nameLength+1:offset+nameLength+1+labelLength]...)
		name = append(name, '.')
		nameLength += labelLength
	}
	// 去掉最后的'.'
	if nameLength != 0 {
		name = name[:len(name)-1]
	} else {
		return ".", offset + 1, nil
	}
	return string(name), offset + nameLength + 1, nil
}

// CountDomainNameLabels 返回域名的标签数量。
func CountDomainNameLabels(name *string) int {
	labelNum := 0
	nameLen := len(*name)
	if (*name)[nameLen-1] == '.' {
		nameLen--
	}
	for i := 0; i < nameLen; i++ {
		if (*name)[i] == '.' {
			labelNum++
		}
	}
	return labelNum + 1
}

// GetCharacterStrWireLen 返回字符串的 编码格式长度。
func GetCharacterStrWireLen(cStr *string) int {
	strLen := len(*cStr)
	if strLen == 0 {
		return 1
	}

	frags := (strLen + 254) / 255
	return strLen + frags
}

// EncodeCharacterStr 编码字符串，其接受字符串，并返回编码后的字节切片。
func EncodeCharacterStr(cStr *string) []byte {
	strLen := len(*cStr)
	if strLen == 0 {
		return []byte{0x00}
	}

	encodedLen := GetCharacterStrWireLen(cStr)
	byteArray := make([]byte, encodedLen)

	rawTvlr := 0
	enTvlr := 0
	for rawTvlr+255 < strLen {
		byteArray[enTvlr] = 255
		copy(byteArray[enTvlr+1:], (*cStr)[rawTvlr:rawTvlr+255])
		rawTvlr += 255
		enTvlr += 256
	}
	if rawTvlr < strLen {
		byteArray[enTvlr] = byte(strLen - rawTvlr)
		copy(byteArray[enTvlr+1:], (*cStr)[rawTvlr:])
	}
	return byteArray
}

// EncodeCharacterStrToBuffer 将字符串编码到字节切片中。
//   - 其接收参数为 字符串 和 字节切片，
//   - 返回值为 编码后长度 及 报错信息。
func EncodeCharacterStrToBuffer(cStr *string, buffer []byte) (int, error) {
	encodedLen := GetCharacterStrWireLen(cStr)
	if len(buffer) < encodedLen {
		return -1, fmt.Errorf(
			"function EncodeCharacterStrToBuffer error: buffer is too small, require %d byte size, but got %d",
			encodedLen, len(buffer))
	}

	strLen := len(*cStr)
	if strLen == 0 {
		buffer[0] = 0x00
		return 1, nil
	}

	rawTvlr := 0
	enTvlr := 0
	for rawTvlr+255 < strLen {
		buffer[enTvlr] = 255
		copy(buffer[enTvlr+1:], (*cStr)[rawTvlr:rawTvlr+255])
		rawTvlr += 255
		enTvlr += 256
	}
	if rawTvlr < strLen {
		buffer[enTvlr] = byte(strLen - rawTvlr)
		copy(buffer[enTvlr+1:], (*cStr)[rawTvlr:])
	}
	return encodedLen, nil
}

// DecodeCharacterStr 解码字符串，其接受字节切片，并返回解码后字符串。
func DecodeCharacterStr(data []byte) string {
	dLen := len(data)
	if dLen == 1 {
		return ""
	}

	rstBytes := make([]byte, dLen)

	rawTvlr := 0
	deTvlr := 0
	for rawTvlr < dLen {
		strLen := int(data[rawTvlr])
		copy(rstBytes[deTvlr:], data[rawTvlr+1:rawTvlr+strLen+1])
		rawTvlr += strLen + 1
		deTvlr += strLen
	}
	return string(rstBytes[:deTvlr])
}

func CanonicalizeDomainName(name *string) string {
	if (*name)[0] == '.' {
		return "."
	}
	return strings.ToLower(*name)
}

type ByCanonicalOrder []DNSResourceRecord

func (rrSet ByCanonicalOrder) Len() int {
	return len(rrSet)
}
func (rrSet ByCanonicalOrder) Swap(i, j int) {
	rrSet[i], rrSet[j] = rrSet[j], rrSet[i]
}
func (rrSet ByCanonicalOrder) Less(i, j int) bool {
	rdataBytesI := rrSet[i].RData.Encode()
	rdataBytesJ := rrSet[j].RData.Encode()
	return string(rdataBytesI) < string(rdataBytesJ)
}

func CanonicalSortRRSet(rrSet []DNSResourceRecord) {
	rrSetLen := len(rrSet)
	if rrSetLen == 0 {
		return
	}
	rrSet = ByCanonicalOrder(rrSet)
}

// DNSMessageCompression 对 DNS 消息进行压缩。
func CompressDNSMessage(msg []byte) ([]byte, error) {
	cMsg := make([]byte, 0, len(msg))
	// 从头部字段提取信息
	nQD := binary.BigEndian.Uint16(msg[4:6])
	nAN := binary.BigEndian.Uint16(msg[6:8])
	nNS := binary.BigEndian.Uint16(msg[8:10])
	nAR := binary.BigEndian.Uint16(msg[10:12])

	cMsg = append(cMsg, msg[:12]...)
	cOffset, mOffset := 12, 12

	nameMap := make(map[string]int)

	cFunc := func() error {
		name, nOffset, err := DecodeDomainNameFromBuffer(msg, mOffset)
		nLen := nOffset - mOffset
		if err != nil {
			return fmt.Errorf("DNSMessageCompression error: %s", err)
		}
		name = CanonicalizeDomainName(&name)
		if _, ok := nameMap[name]; !ok {
			nameMap[name] = cOffset
			cMsg = append(cMsg, msg[mOffset:mOffset+nLen]...)
			cOffset += nLen
			mOffset += nLen
		} else {
			ptr := 0xC000 | nameMap[name]
			cMsg = append(cMsg, byte(ptr>>8), byte(ptr&0xFF))
			cOffset += 2
			mOffset += nLen
		}
		return nil
	}

	// 处理查询部分
	for i := 0; i < int(nQD); i++ {
		// 压缩域名
		cFunc()
		// 处理其他字段
		cMsg = append(cMsg, msg[mOffset:mOffset+4]...)

		cOffset += 4
		mOffset += 4
	}
	// 处理其他部分
	for i := 0; i < int(nAN)+int(nNS)+int(nAR); i++ {
		err := cFunc()
		if err != nil {
			return cMsg, err
		}
		// 处理其他字段
		rdlen := binary.BigEndian.Uint16(msg[mOffset+8 : mOffset+10])
		cMsg = append(cMsg, msg[mOffset:mOffset+10+int(rdlen)]...)
		cOffset += 10 + int(rdlen)
		mOffset += 10 + int(rdlen)
	}

	return cMsg, nil
}
