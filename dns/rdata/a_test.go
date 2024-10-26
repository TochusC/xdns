// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// a.test.go 文件测试了 A 类型 DNS 资源记录的 RDATA 编码。
package rdata

import (
	"bytes"
	"net"
	"testing"

	"github.com/tochusc/godns/utils"
)

// 待测试的 A 资源记录 RDATA
var dnsARDATA = DNSARDATA{
	Address: net.ParseIP("10.10.0.2"),
}

// 期望的 A 资源记录 RDATA 的 编码结果
var expectedEncodedARDATA = []byte{10, 10, 0, 2}

// TestARecordEncode 测试 A 资源记录 RDATA 的编码。
func TestARecordEncode(t *testing.T) {
	encoded := dnsARDATA.Encode()
	if !net.IP(encoded).Equal(dnsARDATA.Address) {
		t.Errorf("ARecordEncode() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, encoded, dnsARDATA.Address)
	}
}

// TestARecordEncodeToBuffer 测试 A 资源记录 RDATA 的编码写入缓冲区。
func TestARecordEncodeToBuffer(t *testing.T) {
	buffer := make([]byte, dnsARDATA.Size())
	n, err := dnsARDATA.EncodeToBuffer(buffer)
	if err != nil {
		t.Errorf("ARecordEncodeToBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, err, nil)
	}
	if n != dnsARDATA.Size() {
		t.Errorf("ARecordEncodeToBuffer() failed:\n%s\ngot:\n%d\nexpected:\n%d",
			utils.ResultMismatch, n, dnsARDATA.Size())
	}
	if !bytes.Equal(buffer, expectedEncodedARDATA) {
		t.Errorf("ARecordEncodeToBuffer() failed:\n%s\ngot:\n%v\nexpected:\n%v",
			utils.ResultMismatch, buffer, expectedEncodedARDATA)
	}
}
