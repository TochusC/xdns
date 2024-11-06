// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// responser.go 文件定义了 Responser 接口及其若干实现范例。
// 可以根据需求自定义实现 Responser 接口，以生成 DNS 回复信息。

package godns

import (
	"fmt"

	"github.com/tochusc/godns/dns"
)

// Responser 是一个 DNS 回复器接口。
// 实现该接口的结构体可以根据 DNS 查询信息生成 DNS 回复信息。
type Responser interface {
	// Response 根据 DNS 查询信息生成 DNS 回复信息。
	// 其参数为：
	//   - qInfo QueryInfo，DNS 查询信息
	// 返回值为：
	//   - ResponseInfo，DNS 回复信息
	//   - error，错误信息
	Response(qInfo ConnectionInfo) (dns.DNSMessage, error)
}

// DullResponser 是一个"笨笨的" Responser 实现。
// 它会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
type DullResponser struct {
	ServerConf DNSServerConfig
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
// DullResponser 会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
func (d *DullResponser) Response(connInfo ConnectionInfo) (dns.DNSMessage, error) {
	qry := dns.DNSMessage{}
	resp := dns.DNSMessage{}

	_, err := qry.DecodeFromBuffer(connInfo.Packet, 0)
	if err != nil {
		fmt.Println("Responser: Error decoding DNS query: ", err)
		return resp, err
	}
	fmt.Println("Responser: Recive DNS Query from %s, QName:%s, QType: %s.",
		connInfo.Address.String(), qry.Question[0].Name, qry.Question[0].Type.String())

	resp = dns.DNSMessage{
		Header: dns.DNSHeader{
			ID:      qry.Header.ID,
			QR:      true,
			OpCode:  dns.DNSOpCodeQuery,
			AA:      true,
			TC:      false,
			RD:      false,
			RA:      false,
			Z:       0,
			RCode:   dns.DNSResponseCodeNoErr,
			QDCount: qry.Header.QDCount,
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
		},
		Question: qry.Question,
		Answer: []dns.DNSResourceRecord{
			{
				Name:  qry.Question[0].Name,
				Type:  qry.Question[0].Type,
				Class: qry.Question[0].Class,
				TTL:   3600,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
			},
		},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	}

	return resp, nil
}

// 下面是一些可能会很有用的工具函数及结构体

// NXDOMAINResponse 是一个默认的NXDOMAIN回复信息。
var NXDOMAINResponse = dns.DNSMessage{
	Header: dns.DNSHeader{
		// ID:      qry.Header.ID,
		QR:     true,
		OpCode: dns.DNSOpCodeQuery,
		AA:     true,
		TC:     false,
		RD:     false,
		RA:     false,
		Z:      0,
		// 很可能会想更改这个RCode
		RCode: dns.DNSResponseCodeNXDomain,
		// QDCount: qry.Header.QDCount,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	},
	// Question:   qry.Question,
	Answer:     []dns.DNSResourceRecord{},
	Authority:  []dns.DNSResourceRecord{},
	Additional: []dns.DNSResourceRecord{},
}

// InitResp 根据查询信息初始化NXDOMAIN回复信息
func InitNXDOMAINResp(qry dns.DNSMessage) dns.DNSMessage {
	resp := dns.DNSMessage{
		Header:     NXDOMAINResponse.Header,
		Answer:     []dns.DNSResourceRecord{},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	}
	resp.Header.ID = qry.Header.ID
	resp.Header.QDCount = qry.Header.QDCount
	resp.Question = qry.Question
	return resp
}

func InitResp(qry dns.DNSMessage, defaultResp dns.DNSMessage) dns.DNSMessage {
	resp := dns.DNSMessage{
		Header:     defaultResp.Header,
		Answer:     []dns.DNSResourceRecord{},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	}
	resp.Header.ID = qry.Header.ID
	resp.Header.QDCount = qry.Header.QDCount
	resp.Question = qry.Question
	return resp
}

// FixCount 修正回复信息中的计数字段
func FixCount(resp *dns.DNSMessage) {
	resp.Header.ANCount = uint16(len(resp.Answer))
	resp.Header.NSCount = uint16(len(resp.Authority))
	resp.Header.ARCount = uint16(len(resp.Additional))
}
