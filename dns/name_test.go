// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// name_test.go 测试name.go文件中的域名编解码功能
package dns

import (
	"bytes"
	"testing"

	"github.com/tochusc/godns/utils"
)

// 测试域名 www.example.com
var testedDomainName = "www.example.com"     // 相对域名
var testedAbsDomainName = "www.example.com." // 绝对域名

// www.example.com. 的域名编码结果
// 3, www, 7, example, 3, com, 0
var expectedEncodedName = []byte{
	0x03, 0x77, 0x77, 0x77,
	0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d,
	0x00,
}

// 测试GetNameWireLength函数
func TestGetNameWireLength(t *testing.T) {
	// 测试相对域名
	nameLength := GetNameWireLength(&testedDomainName)
	expectedLength := len(expectedEncodedName)
	if nameLength != expectedLength {
		t.Errorf("GetNameWireLength() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, nameLength, expectedLength)
	}

	// 测试绝对域名
	nameLength = GetNameWireLength(&testedAbsDomainName)
	if nameLength != expectedLength {
		t.Errorf("GetNameWireLength() failed:\n%s\ngot:%d\nexpected: %d",
			utils.ResultMismatch, nameLength, expectedLength)
	}
}

// 测试EncodeDomainName函数
func TestEncodeDomainName(t *testing.T) {
	// 测试相对域名
	encodedName := EncodeDomainName(&testedDomainName)
	if !bytes.Equal(encodedName, expectedEncodedName) {
		t.Errorf(
			"EncodeDomainName() failed:\n%s\ngot:\n%v\n expected:\n%v",
			utils.ResultMismatch, encodedName, expectedEncodedName)
	}

	// 测试绝对域名
	encodedName = EncodeDomainName(&testedAbsDomainName)
	if !bytes.Equal(encodedName, expectedEncodedName) {
		t.Errorf("EncodeDomainName() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, encodedName, expectedEncodedName)
	}
}

// 测试DecodeDomainName函数
func TestDecodeDomainName(t *testing.T) {
	decodedName := DecodeDomainName(expectedEncodedName)
	if decodedName != testedDomainName {
		t.Errorf("DecodeDomainName() failed:\n%s\ngot: %s\nexpected: %s",
			utils.ResultMismatch, decodedName, testedDomainName)
	}
}

// 测试EncodeDomainNameToBuffer函数
func TestEncodeDomainNameToBuffer(t *testing.T) {
	// 测试能否正确编码
	buffer := make([]byte, len(expectedEncodedName))
	_, err := EncodeDomainNameToBuffer(&testedDomainName, buffer)
	if err != nil {
		t.Errorf("EncodeDomainNameToBuffer() failed:\n%s\ngot: %s\nexpected: nil", utils.ErrorMismatch, err)
	}
	if !bytes.Equal(buffer, expectedEncodedName) {
		t.Errorf("EncodeDomainNameToBuffer() failed:\n%s\ngot: %v\nexpected: %v", utils.ResultMismatch, buffer, expectedEncodedName)
	}

	// 测试能否处理缓冲区过小的情况
	buffer = make([]byte, len(expectedEncodedName)-1)
	_, err = EncodeDomainNameToBuffer(&testedDomainName, buffer)
	if err == nil {
		t.Errorf("EncodeDomainNameToBuffer() failed:\n%s\ngot: nil\nexpected: error", utils.ErrorMismatch)
	}
}

// 测试DecodeDomainNameFromBuffer函数
func TestDecodeDomainNameFromBuffer(t *testing.T) {
	buffer := make([]byte, len(testedDomainName))
	_, err := DecodeDomainNameToBuffer(expectedEncodedName, buffer)
	if err != nil {
		t.Errorf("DecodeDomainNameFromBuffer() failed:\n%s\ngot: \n%s\n\nexpected: nil", utils.ErrorMismatch, err)
	}
	if string(buffer) != testedDomainName {
		t.Errorf("DecodeDomainNameFromBuffer() failed:\n%s\ngot: %v\nexpected: %v", utils.ResultMismatch, buffer, []byte(testedDomainName))
	}
}
