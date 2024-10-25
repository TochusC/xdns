// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// 该文件定义了 DNS 域名的编解码函数。
package dns

import (
	"errors"
	"fmt"
)

// EncodeDomainName 编码域名，其接受字符串，并返回编码后的字节切片。
// 可以接收绝对域名及相对域名，生成的域名都会以'.'(0x00)结尾。
func EncodeDomainName(name *string) []byte {
	var byteArray []byte
	nameLength := len(*name)

	// 绝对域名以'.'结尾，相对域名不以'.'结尾
	if (*name)[nameLength-1] == '.' {
		byteArray = make([]byte, nameLength+1)
	} else {
		byteArray = make([]byte, nameLength+2)
		// 相对域名则在最后加上一个0x00
		byteArray[len(byteArray)+1] = 0x00
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
	return byteArray
}

// TODO: 实现域名指针
// DecodeDomainName 解码域名，其接受字节切片，并返回解码后域名。
// 返回的域名为*相对域名*，即不以'.'结尾。
func DecodeDomainName(data []byte) string {
	var name string
	for index := range name {
		if (data)[index] == 0x00 {
			break
		}
		labelLength := int((data)[index])
		name += string((data)[index+1:index+1+labelLength]) + "."
		index += labelLength
	}
	if name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
}

// EncodeDomainNameToBuffer 将域名编码到字节切片中。
//   - 其接收参数为 域名字符串 和 字节切片，
//   - 返回值为 编码后长度 及 报错信息。
//
// 如果出现错误，返回 -1, 及 相应报错 。
func EncodeDomainNameToBuffer(name *string, buffer []byte) (int, error) {
	nameLength := len(*name)

	// 绝对域名以'.'结尾，相对域名不以'.'结尾
	if (*name)[nameLength-1] == '.' {
		if len(buffer) < nameLength+1 {
			return -1, errors.New(
				fmt.Sprintf("EncodeDomainNameToBuffer Error: buffer is too small, require %d byte size, but got %d\n",
					nameLength+1, len(buffer)))
		}
		nameLength = nameLength + 1
	} else {
		if len(buffer) < nameLength+2 {
			return -1, errors.New(
				fmt.Sprintf("EncodeDomainNameToBuffer Error: buffer is too small, require %d byte size, but got %d\n",
					nameLength+2, len(buffer)))
		}
		// 相对域名则在最后加上一个0x00
		(buffer)[len(buffer)+1] = 0x00
		nameLength = nameLength + 2
	}

	labelLength := 0
	for index := range *name {
		if (*name)[index] == '.' {
			(buffer)[index-labelLength] = byte(labelLength)
			copy((buffer)[index-labelLength+1:], (*name)[index-labelLength:index])
			labelLength = 0
		} else {
			labelLength++
		}
	}
	return nameLength, nil
}

// DecodeDomainNameToBuffer 将解码后的域名写入字节切片中。
// - 其接收参数为 域名的WireFormat 和 字节切片，
// - 返回值为 写入的字节数 及 报错信息。
// 如果出现错误，返回 -1 及 相应报错 。
func DecodeDomainNameFromBuffer(data, name []byte) (int, error) {
	nameLength := 0
	for ; (data)[nameLength] != 0x00; nameLength++ {
		labelLength := int((data)[nameLength])

		if len(name) < nameLength+1+labelLength {
			return -1, errors.New(
				fmt.Sprintf(
					"DecodeDomainNameFromBuffer Error: buffer is too small, require %d byte size, but got %d\n",
					nameLength+1+labelLength, len(name)))
		}

		copy((name)[nameLength:], (data)[nameLength+1:nameLength+1+labelLength])
		nameLength += labelLength
		(name)[nameLength] = '.'
	}
	return nameLength, nil
}

// GetNameWireLength 返回域名的WireFormat长度。
//   - 其接收参数为 域名字符串 的指针，
//   - 返回值为 域名的WireFormat长度。
func GetNameWireLength(name *string) int {
	nameLength := len(*name)
	if (*name)[nameLength-1] == '.' {
		return nameLength + 1
	}
	return nameLength + 2
}

// GetNameWireLengthFromBytes 返回域名的WireFormat长度。
//   - 其接收参数为 域名的WireFormat 的字节切片，
//   - 返回值为 域名的WireFormat长度。
func GetNameWireLengthFromBytes(data []byte) int {
	nameLength := 0
	for ; (data)[nameLength] != 0x00; nameLength++ {
		labelLength := int((data)[nameLength])
		nameLength += labelLength + 1
	}
	return nameLength
}
