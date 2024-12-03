// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// responser.go 文件定义了 Responser 接口及其若干实现范例。
// 可以根据需求自定义实现 Responser 接口，以生成 DNS 回复信息。

package godns

import (
	"fmt"
	"strings"
	"time"

	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

// Responser 是一个 DNS 回复器 接口。
// 实现该接口的结构体将根据 DNS 查询信息生成 DNS 回复信息。
type Responser interface {
	// Response 根据 DNS 查询信息生成 DNS 回复信息。
	// 其参数为：
	//   - qInfo QueryInfo，DNS 查询信息
	// 返回值为：
	//   - ResponseInfo，DNS 回复信息
	//   - error，错误信息
	Response(ConnectionInfo) (dns.DNSMessage, error)
}

// DullResponser 是一个"笨笨的" 回复器实现。
// 它会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
type DullResponser struct {
	ServerConf DNSServerConfig
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
// DullResponser 会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
func (d *DullResponser) Response(connInfo ConnectionInfo) (dns.DNSMessage, error) {
	// 解析查询信息
	qry, err := ParseQuery(connInfo)
	if err != nil {
		return dns.DNSMessage{}, err
	}

	// 初始化 NXDOMAIN 回复信息
	resp := InitNXDOMAIN(qry)

	// 将可能启用0x20混淆的查询名称转换为小写
	qName := strings.ToLower(qry.Question[0].Name)

	// 如果查询类型为 A，则回复 A 记录
	if qry.Question[0].Type == dns.DNSRRTypeA {
		resp.Answer = []dns.DNSResourceRecord{
			{
				Name:  qName,
				Type:  qry.Question[0].Type,
				Class: qry.Question[0].Class,
				TTL:   3600,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
			},
		}

		// 设置回复码为无错误
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}
	// 修正计数字段，返回回复信息
	FixCount(&resp)
	return resp, nil
}

// 下面是一些可能会很有用的工具函数及结构体，
// 可以使用/参考这些函数及结构体来实现自定义的 Responser 接口。

// ParseQuery 解析 DNS 查询信息
// 其接受参数为：
//   - connInfo ConnectionInfo，连接信息
//
// 返回值为：
//   - dns.DNSMessage，解析后的 DNS 查询信息
//   - error，错误信息
func ParseQuery(connInfo ConnectionInfo) (dns.DNSMessage, error) {
	qry := dns.DNSMessage{}
	_, err := qry.DecodeFromBuffer(connInfo.Packet, 0)
	if err != nil {
		fmt.Printf("[%s]Responser: Error decoding DNS query: %s\n", time.Now().UTC().String(), err)
		return dns.DNSMessage{}, err
	}
	fmt.Printf("[%s]Responser: Recive DNS Query from %s,Protocol: %s,  QName: %s, QType: %s\n",
		time.Now().UTC().String(), connInfo.Address.String(), connInfo.Protocol.String(),
		qry.Question[0].Name, qry.Question[0].Type.String())

	return qry, nil
}

// NXDOMAINResponse 是一个默认的 NXDOMAIN 回复信息。
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

// InitNXDOMAIN 根据查询信息初始化 NXDOMAIN 回复信息
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//
// 返回值为：
//   - dns.DNSMessage，初始化后的 NXDOMAIN 回复信息
//
// 该函数会返回具有相同 ID 和 Question 字段的 NXDOMAIN 回复信息
func InitNXDOMAIN(qry dns.DNSMessage) dns.DNSMessage {
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

// InitRespone 根据查询信息初始化传入的 默认回复信息
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - defaultResp dns.DNSMessage，默认回复信息
//
// 返回值为：
//   - dns.DNSMessage，初始化后的回复信息
//
// 该函数会将回复信息的 ID 和 Question 字段设置为查询信息的对应字段
func InitResponse(qry dns.DNSMessage, defaultResp dns.DNSMessage) dns.DNSMessage {
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

// DNSSECResponser 是一个支持 DNSSEC 的 回复器 实现范例，
// 它会回复启用DNSSEC签名后的A记录信息，
// 基本上是开启DNSSEC后的 “笨笨回复器”。
type DNSSECResponser struct {
	ServerConf    DNSServerConfig
	DNSSECManager BaseManager
}

type DNSSECManager interface {
	EnableDNSSEC(qry dns.DNSMessage, resp *dns.DNSMessage)
	SignSection(section []dns.DNSResourceRecord) []dns.DNSResourceRecord
	SignRRSet(rrset []dns.DNSResourceRecord) dns.DNSResourceRecord
	EstablishToC(qry dns.DNSMessage, resp *dns.DNSMessage) error
	GetDNSSECMaterial(zName string) DNSSECMaterial
	CreateDNSSECMaterial(zName string) DNSSECMaterial
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d *DNSSECResponser) Response(connInfo ConnectionInfo) (dns.DNSMessage, error) {
	// 解析查询信息
	qry, err := ParseQuery(connInfo)
	if err != nil {
		return dns.DNSMessage{}, err
	}

	// 初始化 NXDOMAIN 回复信息
	resp := InitNXDOMAIN(qry)

	qType := qry.Question[0].Type

	// 如果查询类型为 A，则回复 A 记录
	if qType == dns.DNSRRTypeA {
		// 将可能启用0x20混淆的查询名称转换为小写
		qName := strings.ToLower(qry.Question[0].Name)

		// 生成 A 记录
		rr := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
		}
		resp.Answer = append(resp.Answer, rr)
	}

	// 为回复信息添加 DNSSEC 记录
	d.DNSSECManager.EnableDNSSEC(qry, &resp)

	// 设置RCODE，修正计数字段，返回回复信息
	resp.Header.RCode = dns.DNSResponseCodeNoErr
	FixCount(&resp)
	return resp, nil
}

// BaseManager 是一个 DNSSEC 管理器 实现范例。
// 它会根据查询信息生成 DNSSEC 签名后的 DNS 回复信息。
// 该结构体可以用于一键化支持 DNSSEC。
// 如果要实现更为复杂的 DNSSEC 管理逻辑，可以根据需求自定义 BaseManager 结构体。
type BaseManager struct {
	// DNSSEC 配置
	DNSSECConf DNSSECConfig
	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化 DNSSEC Responser 时需要为其手动添加信任锚点
	DNSSECMap map[string]DNSSECMaterial
}

// DNSSECConfig 表示 DNSSEC 签名配置
// 如果需要多种签名配置，可以根据需求实现自己的签名配置结构体
type DNSSECConfig struct {
	// DNSSEC 签名算法
	DAlgo dns.DNSSECAlgorithm
	// DNSSEC 摘要算法
	DType dns.DNSSECDigestType
}

// DNSSECMaterial 表示签名一个区域所需的 DNSSEC 材料
// 如果需要更复杂的处理逻辑，可以根据需求实现自己的 DNSSEC 材料结构体
type DNSSECMaterial struct {
	// KSKTag 是区域的 KSK 标签
	KSKTag int
	// ZSKTag 是区域的 ZSK 标签
	ZSKTag int
	// PrivateKSK 是区域的 KSK 私钥
	PrivateKSK []byte
	// PrivateZSK 是区域的 ZSK 私钥
	PrivateZSK []byte
	// DNSKEYRespSec 储存区域的 DNSKEY 记录
	DNSKEYRespSec []dns.DNSResourceRecord
}

// EnableDNSSEC 检查 DNS 回复信息，并对其进行 DNSSEC 签名，
// 实现一键化支持 DNSSEC。
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - resp *dns.DNSMessage，回复信息
//
// 该函数会为传入的回复信息自动添加相关的 DNSSEC 记录，
// 目前尚未实现 规范化排序 功能，需要确保传入回复信息中的记录已经按照规范化排序，
// 否则会导致签名失败。
func (d *BaseManager) EnableDNSSEC(qry dns.DNSMessage, resp *dns.DNSMessage) {
	// 签名回答部分
	rMap := make(map[string][]dns.DNSResourceRecord)
	for _, rr := range resp.Answer {
		if rr.Type == dns.DNSRRTypeRRSIG {
			continue
		}
		rid := rr.Name + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rr.Name], rr)
	}
	for _, rrset := range rMap {
		uName := dns.GetUpperDomainName(&rrset[0].Name)
		dMat := GetDNSSECMaterial(d.DNSSECConf, d.DNSSECMap, uName)
		sig := xperi.GenerateRRRRSIG(
			rrset,
			d.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			uName,
			dMat.PrivateZSK,
		)
		resp.Answer = append(resp.Answer, sig)
	}

	// 签名权威部分
	rMap = make(map[string][]dns.DNSResourceRecord)
	for _, rr := range resp.Authority {
		if rr.Type == dns.DNSRRTypeRRSIG {
			continue
		}
		rid := rr.Name + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rr.Name], rr)
	}
	for _, rrset := range rMap {
		uName := dns.GetUpperDomainName(&rrset[0].Name)
		dMat := GetDNSSECMaterial(d.DNSSECConf, d.DNSSECMap, uName)
		sig := xperi.GenerateRRRRSIG(
			rrset,
			d.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			uName,
			dMat.PrivateZSK,
		)
		resp.Authority = append(resp.Authority, sig)
	}

	// 签名附加部分
	rMap = make(map[string][]dns.DNSResourceRecord)
	for _, rr := range resp.Additional {
		if rr.Type == dns.DNSRRTypeRRSIG {
			continue
		}
		rid := rr.Name + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rr.Name], rr)
	}
	for _, rrset := range rMap {
		uName := dns.GetUpperDomainName(&rrset[0].Name)
		dMat := GetDNSSECMaterial(d.DNSSECConf, d.DNSSECMap, uName)
		sig := xperi.GenerateRRRRSIG(
			rrset,
			d.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			uName,
			dMat.PrivateZSK,
		)
		resp.Additional = append(resp.Additional, sig)
	}

	// 建立信任链
	EstablishToC(qry, d.DNSSECConf, d.DNSSECMap, resp)
}

// CreateDNSSECMaterial 根据 DNSSEC 配置生成指定区域的 DNSSEC 材料
// 其接受参数为：
//   - dConf DNSSECConfig，DNSSEC 配置
//   - zName string，区域名
//
// 返回值为：
//   - DNSSECMaterial，生成的 DNSSEC 材料
//
// 该函数会为指定区域生成一个 KSK 和一个 ZSK，并生成一个 DNSKEY 记录和一个 RRSIG 记录。
func CreateDNSSECMaterial(dConf DNSSECConfig, zName string) DNSSECMaterial {
	pubKSK, privKSKBytes := xperi.GenerateRRDNSKEY(zName, dConf.DAlgo, dns.DNSKEYFlagSecureEntryPoint)
	pubZSK, privZSKBytes := xperi.GenerateRRDNSKEY(zName, dConf.DAlgo, dns.DNSKEYFlagZoneKey)
	kSKTag := xperi.CalculateKeyTag(*pubKSK.RData.(*dns.DNSRDATADNSKEY))
	zSKTag := xperi.CalculateKeyTag(*pubZSK.RData.(*dns.DNSRDATADNSKEY))
	// 生成密钥集签名
	keySig := xperi.GenerateRRRRSIG(
		[]dns.DNSResourceRecord{
			pubZSK,
			pubKSK,
		},
		dns.DNSSECAlgorithmECDSAP384SHA384,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		kSKTag,
		zName,
		privKSKBytes,
	)
	// 生成 DNSSEC 材料
	anSec := []dns.DNSResourceRecord{
		pubZSK,
		pubKSK,
		keySig,
	}
	return DNSSECMaterial{
		KSKTag:        int(kSKTag),
		ZSKTag:        int(zSKTag),
		PrivateKSK:    privKSKBytes,
		PrivateZSK:    privZSKBytes,
		DNSKEYRespSec: anSec,
	}
}

// GetDNSSECMaterial 获取指定区域的 DNSSEC 材料
// 如果该区域的 DNSSEC 材料不存在，则会根据 DNSSEC 配置生成一个
func GetDNSSECMaterial(dConf DNSSECConfig, dMap map[string]DNSSECMaterial, zName string) DNSSECMaterial {
	dMat, ok := dMap[zName]
	if !ok {
		dMap[zName] = CreateDNSSECMaterial(dConf, zName)
		dMat = dMap[zName]
	}
	return dMat
}

// EstablishToC 根据查询自动添加 DNSKEY，DS，RRSIG 记录
// 自动完成信任链（Trust of Chain）的建立。
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - dConf DNSSECConfig，DNSSEC 配置
//   - dMap map[string]DNSSECMaterial，区域名与其相应 DNSSEC 材料的映射
//   - resp *dns.DNSMessage，回复信息
func EstablishToC(qry dns.DNSMessage, dConf DNSSECConfig, dMap map[string]DNSSECMaterial, resp *dns.DNSMessage) error {
	// 提取查询类型和查询名称
	qType := qry.Question[0].Type
	qName := strings.ToLower(qry.Question[0].Name)
	dMat := GetDNSSECMaterial(dConf, dMap, qName)

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		resp.Answer = append(resp.Answer, dMat.DNSKEYRespSec...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dMat := GetDNSSECMaterial(dConf, dMap, qName)
		ds := xperi.GenerateRRDS(
			qName,
			*dMat.DNSKEYRespSec[1].RData.(*dns.DNSRDATADNSKEY),
			dConf.DType,
		)

		// 生成 ZSK 签名
		upName := dns.GetUpperDomainName(&qName)
		dMat = GetDNSSECMaterial(dConf, dMap, upName)
		sig := xperi.GenerateRRRRSIG(
			[]dns.DNSResourceRecord{ds},
			dConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			upName,
			dMat.PrivateZSK,
		)
		resp.Answer = append(resp.Answer, ds, sig)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}
	FixCount(resp)
	return nil
}

// InitTrustAnchor 根据 DNSSEC 配置生成指定区域的信任锚点
// 其接受参数为：
//   - zName string，区域名
//   - dConf DNSSECConfig，DNSSEC 配置
//   - kBytes []byte，KSK 公钥
//   - pkBytes []byte，KSK 私钥
//
// 返回值为：
//   - map[string]DNSSECMaterial，生成的信任锚点
func InitTrustAnchor(zName string, dConf DNSSECConfig,
	kBytes, pkBytes []byte) map[string]DNSSECMaterial {
	kRDATA := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  dns.DNSKEYProtocolValue,
		Algorithm: dConf.DAlgo,
		PublicKey: kBytes,
	}
	zRR, pzBytes := xperi.GenerateRRDNSKEY(zName, dConf.DAlgo, dns.DNSKEYFlagZoneKey)
	zRDATA := zRR.RData.(*dns.DNSRDATADNSKEY)

	kTag := xperi.CalculateKeyTag(kRDATA)
	zTag := xperi.CalculateKeyTag(*zRDATA)

	kRR := dns.DNSResourceRecord{
		Name:  zName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(kRDATA.Size()),
		RData: &kRDATA,
	}

	kSig := xperi.GenerateRRRRSIG(
		[]dns.DNSResourceRecord{zRR, kRR},
		dConf.DAlgo,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(kTag),
		zName,
		pkBytes,
	)

	return map[string]DNSSECMaterial{
		zName: {
			KSKTag:        int(kTag),
			ZSKTag:        int(zTag),
			PrivateKSK:    pkBytes,
			PrivateZSK:    pzBytes,
			DNSKEYRespSec: []dns.DNSResourceRecord{zRR, kRR, kSig},
		},
	}
}
