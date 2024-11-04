// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// responser.go 文件定义了 Responser 接口和 DullResponser 结构体。

package godns

import (
	"time"

	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
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

// 下面是一些可能会很有用的工具函数及结构体

// DefaultResponse 是一个默认的NXDOMAIN回复信息。
var DefaultResponse = ResponseInfo{
	// MAC:  qInfo.MAC,
	// IP:   qInfo.IP,
	// Port: qInfo.Port,
	DNS: &dns.DNSMessage{
		Header: dns.DNSHeader{
			// ID:      qInfo.DNS.Header.ID,
			QR:     true,
			OpCode: dns.DNSOpCodeQuery,
			AA:     true,
			TC:     false,
			RD:     false,
			RA:     false,
			Z:      0,
			// 很可能会想更改这个RCode
			RCode: dns.DNSResponseCodeNXDomain,
			// QDCount: qInfo.DNS.Header.QDCount,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		// Question:   qInfo.DNS.Question,
		Answer:     []dns.DNSResourceRecord{},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	},
}

// InitResp 根据查询信息初始化回复信息
func InitResp(qInfo QueryInfo) ResponseInfo {
	rInfo := DefaultResponse
	rInfo.MAC = qInfo.MAC
	rInfo.IP = qInfo.IP
	rInfo.Port = qInfo.Port
	rInfo.DNS = &dns.DNSMessage{
		Header:     DefaultResponse.DNS.Header,
		Answer:     []dns.DNSResourceRecord{},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	}
	rInfo.DNS.Header.ID = qInfo.DNS.Header.ID
	rInfo.DNS.Header.QDCount = qInfo.DNS.Header.QDCount
	rInfo.DNS.Question = qInfo.DNS.Question
	return rInfo
}

// FixCount 修正回复信息中的计数字段
func FixCount(rInfo *ResponseInfo) {
	rInfo.DNS.Header.ANCount = uint16(len(rInfo.DNS.Answer))
	rInfo.DNS.Header.NSCount = uint16(len(rInfo.DNS.Authority))
	rInfo.DNS.Header.ARCount = uint16(len(rInfo.DNS.Additional))
}

// InitTrustAnchor 生成信任锚点
func InitTrustAnchor(zoneName string, dConf DNSSECConfig, pubKeyBytes, privKeyBytes []byte) DNSSECMaterial {
	pubKskRDATA := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  dns.DNSKEYProtocolValue,
		Algorithm: dConf.DAlgo,
		PublicKey: pubKeyBytes,
	}

	pubZskRDATA, privZskBytes := xperi.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagZoneKey)
	pubZskRR := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(pubZskRDATA.Size()),
		RData: &pubZskRDATA,
	}
	pubKskRR := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(pubKskRDATA.Size()),
		RData: &pubKskRDATA,
	}

	// 生成密钥集签名
	keySetSig := xperi.GenerateRRSIG(
		[]dns.DNSResourceRecord{
			pubZskRR,
			pubKskRR,
		},
		dConf.DAlgo,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(xperi.CalculateKeyTag(pubKskRDATA)),
		zoneName,
		privKeyBytes,
	)
	sigRec := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(keySetSig.Size()),
		RData: &keySetSig,
	}
	// 生成 DNSSEC 材料
	anSec := []dns.DNSResourceRecord{
		pubZskRR,
		pubKskRR,
		sigRec,
	}
	return DNSSECMaterial{
		KSKTag:        int(xperi.CalculateKeyTag(pubKskRDATA)),
		ZSKTag:        int(xperi.CalculateKeyTag(pubZskRDATA)),
		PrivateKSK:    privKeyBytes,
		PrivateZSK:    privZskBytes,
		DNSKEYRespSec: anSec,
	}
}

// 一个可能的 Responser 实现示例
// StatefulResponser 是一个"有状态的" Responser 实现。
// 它能够“记住”每个客户端的查询次数和查询记录。
// 可以根据这些信息来生成不同的回复，或者在此基础上实现更复杂的逻辑。
type StatefulResponser struct {
	// 服务器配置
	ServerConf DNSServerConfig
	// 可以设置其他的默认回复
	DefaultResp ResponseInfo
	// 客户端IP -> 客户端信息的映射
	ClientMap  map[string]ClientInfo
	MyResponse func(*StatefulResponser, *ResponseInfo) error
}

// ClientInfo 客户端信息
// 根据需求不同，可以在这里添加更多的字段。
type ClientInfo struct {
	// 查询次数
	QueryTimes int
	// 查询记录
	QueryList []QueryInfo
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d StatefulResponser) Response(qInfo QueryInfo) (ResponseInfo, error) {
	d.RegisterClient(qInfo)
	rInfo := d.InitResp(qInfo)

	// 可以在这里随意地构造回复...
	err := d.MyResponse(&d, &rInfo)
	if err != nil {
		return rInfo, err
	}

	FixCount(&rInfo)
	return rInfo, nil
}

// RegisterClient 记录客户端信息
func (d *StatefulResponser) RegisterClient(qInfo QueryInfo) {
	qIP := qInfo.IP.String()
	if _, ok := d.ClientMap[qIP]; !ok {
		d.ClientMap[qIP] = ClientInfo{
			QueryTimes: 1,
			QueryList:  []QueryInfo{},
		}
	} else {
		clientInfo := d.ClientMap[qIP]
		clientInfo.QueryTimes++
		clientInfo.QueryList = append(clientInfo.QueryList, qInfo)
		d.ClientMap[qIP] = clientInfo
	}
}

// 可以设置自己的InitResp函数
func (d StatefulResponser) InitResp(qInfo QueryInfo) ResponseInfo {
	rInfo := d.DefaultResp
	rInfo.MAC = qInfo.MAC
	rInfo.IP = qInfo.IP
	rInfo.Port = qInfo.Port
	rInfo.DNS = &dns.DNSMessage{
		Header:     d.DefaultResp.DNS.Header,
		Answer:     []dns.DNSResourceRecord{},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	}
	rInfo.DNS.Header.ID = qInfo.DNS.Header.ID
	rInfo.DNS.Header.QDCount = qInfo.DNS.Header.QDCount
	rInfo.DNS.Question = qInfo.DNS.Question
	return rInfo
}

// DNSSECResponser 是一个实现了 DNSSEC 的 Responser 实现。
// 它默认会回复指向服务器的A记录，并自动为子区域生成对应的
// DNSKEY, RRSIG, DS等相关记录。
// 可以根据需求在这里实现 DNSSEC 的相关逻辑。
// 也可以在此基础上实现更复杂的逻辑。
type DNSSECResponser struct {
	// 服务器配置
	ServerConf DNSServerConfig
	DNSSECConf DNSSECConfig
	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化DNSSEC Responser 时很可能需要为其手动添加信任锚点
	DNSSECMap map[string]DNSSECMaterial
	// 自定义的回复函数
	MyResponse func(*DNSSECResponser, *ResponseInfo) error
}

type DNSSECConfig struct {
	DAlgo dns.DNSSECAlgorithm
	DType dns.DNSSECDigestType
}

type DNSSECMaterial struct {
	KSKTag        int
	ZSKTag        int
	PrivateKSK    []byte
	PrivateZSK    []byte
	DNSKEYRespSec []dns.DNSResourceRecord
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d DNSSECResponser) Response(qInfo QueryInfo) (ResponseInfo, error) {
	rInfo := InitResp(qInfo)
	d.EnableDNSSEC(qInfo, &rInfo)

	// 在这里可以随意构造回复：
	err := d.MyResponse(&d, &rInfo)
	if err != nil {
		return rInfo, err
	}

	FixCount(&rInfo)
	return rInfo, nil
}

// EnableDNSSEC 根据查询自动添加相关的 DNSSEC 记录
func (d DNSSECResponser) EnableDNSSEC(qInfo QueryInfo, rInfo *ResponseInfo) error {
	// 提取查询类型和查询名称
	qType := qInfo.DNS.Question[0].Type
	qName := qInfo.DNS.Question[0].Name

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		dnssecMat := d.GetDNSSECMat(qName)
		rInfo.DNS.Answer = append(rInfo.DNS.Answer, dnssecMat.DNSKEYRespSec...)
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dnssecMat := d.GetDNSSECMat(qName)
		ds := xperi.GenerateDS(
			qName,
			*dnssecMat.DNSKEYRespSec[1].RData.(*dns.DNSRDATADNSKEY),
			d.DNSSECConf.DType,
		)
		rec := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeDS,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(ds.Size()),
			RData: &ds,
		}

		// 生成 ZSK 签名
		upperName := dns.GetUpperDomainName(&qName)
		dnssecMat = d.GetDNSSECMat(upperName)
		sig := xperi.GenerateRRSIG(
			[]dns.DNSResourceRecord{rec},
			d.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dnssecMat.ZSKTag),
			upperName,
			dnssecMat.PrivateZSK,
		)
		sigRec := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeRRSIG,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(sig.Size()),
			RData: &sig,
		}
		rInfo.DNS.Answer = append(rInfo.DNS.Answer, rec, sigRec)
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
	}
	FixCount(rInfo)
	return nil
}

func (d DNSSECResponser) CreateDNSSECMat(zoneName string) DNSSECMaterial {
	pubKskRDATA, privKskBytes := xperi.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagSecureEntryPoint)
	pubZskRDATA, privZskBytes := xperi.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagZoneKey)
	pubZskRR := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(pubZskRDATA.Size()),
		RData: &pubZskRDATA,
	}
	pubKskRR := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(pubKskRDATA.Size()),
		RData: &pubKskRDATA,
	}

	// 生成密钥集签名
	keySetSig := xperi.GenerateRRSIG(
		[]dns.DNSResourceRecord{
			pubZskRR,
			pubKskRR,
		},
		dns.DNSSECAlgorithmECDSAP384SHA384,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(xperi.CalculateKeyTag(pubKskRDATA)),
		zoneName,
		privKskBytes,
	)
	sigRec := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(keySetSig.Size()),
		RData: &keySetSig,
	}
	// 生成 DNSSEC 材料
	anSec := []dns.DNSResourceRecord{
		pubZskRR,
		pubKskRR,
		sigRec,
	}
	return DNSSECMaterial{
		KSKTag:        int(xperi.CalculateKeyTag(pubKskRDATA)),
		ZSKTag:        int(xperi.CalculateKeyTag(pubZskRDATA)),
		PrivateKSK:    privKskBytes,
		PrivateZSK:    privZskBytes,
		DNSKEYRespSec: anSec,
	}
}

func (d DNSSECResponser) GetDNSSECMat(zoneName string) DNSSECMaterial {
	dnssecMat, ok := d.DNSSECMap[zoneName]
	if !ok {
		d.DNSSECMap[zoneName] = d.CreateDNSSECMat(zoneName)
		dnssecMat = d.DNSSECMap[zoneName]
	}
	return dnssecMat
}
