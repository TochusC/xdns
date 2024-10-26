// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// name.go 文件定义了 DNS 域名的编解码函数。
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
		return nameLength + 1
	}
	return nameLength + 2
}

// EncodeDomainName 编码域名，其接受字符串，并返回编码后的字节切片。
// 可以接收绝对域名及相对域名，生成的域名都会以'.'(0x00)结尾。
func EncodeDomainName(name *string) []byte {
	encodedLength := GetNameWireLength(name)
	byteArray := make([]byte, encodedLength)

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
		name = name[:len(name)-1]
	}
	return name
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
				"DecodeDomainNameFromBuffer Error:\nbuffer is too small, require %d byte size, but got %d",
				offset+nameLength+1+labelLength, dataLength)
		}

		name = append(name, data[offset+nameLength+1:offset+nameLength+1+labelLength]...)
		name = append(name, '.')
		nameLength += labelLength
	}
	// 去掉最后的'.'
	if nameLength != 0 {
		name = name[:len(name)-1]
	}
	return string(name), offset + nameLength + 1, nil
}

// DecodeDomainNameToBuffer 将解码后的域名写入字节切片中。
// - 其接收参数为 域名的WireFormat 和 字节切片，
// - 返回值为 写入的字节数 及 报错信息。
// 如果出现错误，返回 -1 及 相应报错 。
func DecodeDomainNameToBuffer(data, buffer []byte) (int, error) {
	nameLength := 0
	for ; data[nameLength] != 0x00; nameLength++ {
		labelLength := int(data[nameLength])

		if len(buffer) < nameLength+labelLength {
			return -1, fmt.Errorf(
				"DecodeDomainNameFromBuffer Error: buffer is too small, require %d byte size, but got %d",
				nameLength+1+labelLength, len(buffer))
		}

		copy(buffer[nameLength:], data[nameLength+1:nameLength+1+labelLength])
		nameLength += labelLength

		// 如果不是最后一个标签，则加上'.'
		if data[nameLength+1] != 0x00 {
			buffer[nameLength] = '.'
		}
	}
	return nameLength, nil
}
