// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// name.go 文件定义了 DNS 域名的编解码函数。
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

package dns

import (
	"fmt"
)

// GetNameWireLength 返回域名的 编码格式长度。
//   - 其接收参数为 域名字符串 的指针，
//   - 返回值为域名的 编码格式长度。
//
// 可以接收绝对域名及相对域名，所有域名均以绝对域名的长度计算。
func GetNameWireLength(name *string) int {
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

// EncodeDomainName 编码域名，其接受字符串，并返回编码后的字节切片。
// 可以接收绝对域名及相对域名，生成的域名都会以'.'(0x00)结尾。
func EncodeDomainName(name *string) []byte {
	encodedLength := GetNameWireLength(name)
	byteArray := make([]byte, encodedLength)

	// 根域名，返回0x00
	if encodedLength == 1 {
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
		byteArray[encodedLength-labelLength-2] = byte(labelLength)
		copy(byteArray[encodedLength-labelLength-1:], (*name)[len(*name)-labelLength:])
	}
	return byteArray
}

// EncodeDomainNameToBuffer 将域名编码到字节切片中。
//   - 其接收参数为 域名字符串 和 字节切片，
//   - 返回值为 编码后长度 及 报错信息。
//
// 如果出现错误，返回 -1, 及 相应报错 。
func EncodeDomainNameToBuffer(name *string, buffer []byte) (int, error) {
	encodedLength := GetNameWireLength(name)
	if len(buffer) < encodedLength {
		return -1, fmt.Errorf(
			"EncodeDomainNameToBuffer Error: buffer is too small, require %d byte size, but got %d",
			encodedLength, len(buffer))
	}

	if encodedLength == 1 {
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
		buffer[encodedLength-labelLength-2] = byte(labelLength)
		copy(buffer[encodedLength-labelLength-1:], (*name)[len(*name)-labelLength:])
	}
	return encodedLength, nil
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
			"DecodeDomainNameFromBuffer Error:\nbuffer is too small, require %d byte size, but got %d",
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
			nameLength++
			break
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
