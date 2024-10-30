// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// responser.go 文件定义了 Responser 接口和 DullResponser 结构体。

package godns

import "github.com/tochusc/godns/dns"

// Responser 是一个 DNS 回复器接口。
// 实现该接口的结构体可以根据 DNS 查询信息生成 DNS 回复信息。
type Responser interface {
	// Response 根据 DNS 查询信息生成 DNS 回复信息。
	// 其参数为：
	//   - qInfo QueryInfo，DNS 查询信息
	// 返回值为：
	//   - ResponseInfo，DNS 回复信息
	//   - error，错误信息
	Response(qInfo QueryInfo) (ResponseInfo, error)
}

// DullResponser 是一个"笨笨的" Responser 实现。
// 它会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
type DullResponser struct {
	ServerConf DNSServerConfig
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
// DullResponser 会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
func (d DullResponser) Response(qInfo QueryInfo) (ResponseInfo, error) {
	return ResponseInfo{
		MAC:  qInfo.MAC,
		IP:   qInfo.IP,
		Port: qInfo.Port,
		DNS: &dns.DNSMessage{
			Header: dns.DNSHeader{
				ID:      qInfo.DNS.Header.ID,
				QR:      true,
				OpCode:  dns.DNSOpCodeQuery,
				AA:      true,
				TC:      false,
				RD:      false,
				RA:      false,
				Z:       0,
				RCode:   dns.DNSResponseCodeNoErr,
				QDCount: qInfo.DNS.Header.QDCount,
				ANCount: 1,
				NSCount: 0,
				ARCount: 0,
			},
			Question: qInfo.DNS.Question,
			Answer: []dns.DNSResourceRecord{
				{
					Name:  qInfo.DNS.Question[0].Name,
					Type:  qInfo.DNS.Question[0].Type,
					Class: qInfo.DNS.Question[0].Class,
					TTL:   3600,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
				},
			},
			Authority:  []dns.DNSResourceRecord{},
			Additional: []dns.DNSResourceRecord{},
		},
	}, nil
}
