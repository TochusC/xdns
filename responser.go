// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// responser.go 文件定义了 Responser 接口及其若干实现范例。
// 可以根据需求自定义实现 Responser 接口，以生成 DNS 回复信息。

package xdns

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/tochusc/xdns/dns"
	"github.com/tochusc/xdns/dns/xperi"
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
	Response(ConnectionInfo) ([]byte, error)
}

// DullResponser 是一个"笨笨的" 回复器实现。
// 它会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
type DullResponser struct {
	ServerConf ServerConfig
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
// DullResponser 会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
func (d *DullResponser) Response(connInfo ConnectionInfo) ([]byte, error) {
	// 解析查询信息
	qry, err := ParseQuery(connInfo)
	if err != nil {
		return []byte{}, err
	}

	// 初始化 NXDOMAIN 回复信息
	resp := InitNXDOMAIN(qry)

	// 将可能启用0x20混淆的查询名称转换为小写
	qName := strings.ToLower(qry.Question[0].Name.DomainName)

	// 如果查询类型为 A，则回复 A 记录
	if qry.Question[0].Type == dns.DNSRRTypeA {
		resp.Answer = []dns.DNSResourceRecord{
			{
				Name:  *dns.NewDNSName(qName),
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
	return resp.Encode(), nil
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
		return dns.DNSMessage{}, fmt.Errorf("Error decoding query: %v", err)
	}
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
	ServerConf    ServerConfig
	DNSSECManager BaseManager
}

type DNSSECManager interface {
	EnableDNSSEC(qry dns.DNSMessage, resp *dns.DNSMessage)
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
		qName := strings.ToLower(qry.Question[0].Name.DomainName)

		// 生成 A 记录
		rr := dns.DNSResourceRecord{
			Name:  *dns.NewDNSName(qName),
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
		}
		resp.Answer = append(resp.Answer, rr)
	}

	// 为回复信息添加 DNSSEC 记录
	EnableDNSSEC(qry, &resp, d.DNSSECManager.Config, &d.DNSSECManager.MaterialMap)

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
	Config DNSSECConfig
	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化 DNSSEC Responser 时需要为其手动添加信任锚点
	MaterialMap sync.Map
}

// DNSSECConfig 表示 DNSSEC 签名配置
// 如果需要多种签名配置，可以根据需求实现自己的签名配置结构体
type DNSSECConfig struct {
	// DNSSEC 签名算法
	Algo dns.DNSSECAlgorithm
	// DNSSEC 摘要算法
	Type dns.DNSSECDigestType

	// 签名过期时间
	Expiration uint32
	// 签名生效时间
	Inception uint32
}

// DNSSECMaterial 表示签名一个区域所需的 DNSSEC 材料
// 如果需要更复杂的处理逻辑，可以根据需求实现自己的 DNSSEC 材料结构体
type DNSSECMaterial struct {
	// KeyTag
	ZSKTag int
	KSKTag int

	// 公钥RDATA
	ZSKRecord dns.DNSResourceRecord
	KSKRecord dns.DNSResourceRecord

	// 私钥字节
	ZSKPriv []byte
	KSKPriv []byte
}

type CryptoMaterial struct {
	// 签名算法
	Algorithm dns.DNSSECAlgorithm
	// 签名过期时间
	Expiration uint32
	// 签名生效时间
	Inception uint32
	// 密钥标签
	KeyTag uint16
	// 签名者名称
	SignerName string
	// 私钥字节
	PrivateKey []byte
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
func EnableDNSSEC(qry dns.DNSMessage, resp *dns.DNSMessage, dConf DNSSECConfig, dMap *sync.Map) {
	qName := strings.ToLower(qry.Question[0].Name.DomainName)
	upperName := dns.GetUpperDomainName(&qName)
	// 获取 DNSSEC 材料
	dMat := GetDNSSECMaterial(upperName, dMap, dConf)
	// 获取 ZSK 的相关信息
	zTag := dMat.ZSKTag
	zPriv := dMat.ZSKPriv
	zAlgo := dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY).Algorithm

	cMat := CryptoMaterial{
		Algorithm:  zAlgo,
		Expiration: dConf.Expiration,
		Inception:  dConf.Inception,
		KeyTag:     uint16(zTag),
		SignerName: upperName,
		PrivateKey: zPriv,
	}

	// 签名回答部分
	resp.Answer = SignSection(resp.Answer, cMat)
	// 签名权威部分
	resp.Authority = SignSection(resp.Authority, cMat)
	// 签名附加部分
	resp.Additional = SignSection(resp.Additional, cMat)

	// 建立信任链
	EstablishCoT(qry, resp, dConf, dMap)
}

// SignSection 为指定的DNS回复消息中的区域(Answer, Authority, Addition)进行签名
// 其接受参数为：
//   - section []dns.DNSResourceRecord，待签名的区域(Answer, Authority, Addition)信息
//
// 返回值为：
//   - []dns.DNSResourceRecord，签名后的区域(Answer, Authority, Addition)信息
func SignSection(section dns.DNSResponseSection, crypto CryptoMaterial) []dns.DNSResourceRecord {
	rMap := make(map[string][]dns.DNSResourceRecord)
	for _, rr := range section {
		if rr.Type == dns.DNSRRTypeRRSIG {
			continue
		}
		rid := rr.Name.DomainName + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rid], rr)
	}
	for _, rrset := range rMap {
		sig := SignSet(rrset, crypto)
		section = append(section, sig)
	}
	return section
}

// SignSet 为指定的 RR 集合签名
// 其接受参数为
//   - rrset []dns.DNSResourceRecord，RR 集合
func SignSet(rrset []dns.DNSResourceRecord, crypto CryptoMaterial) dns.DNSResourceRecord {
	sort.Sort(dns.ByCanonicalOrder(rrset))

	sig := xperi.GenerateRRRRSIG(
		rrset,
		crypto.Algorithm,
		crypto.Expiration,
		crypto.Inception,
		crypto.KeyTag,
		crypto.SignerName,
		crypto.PrivateKey,
	)
	return sig
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
	kskRR, kskPriv := xperi.GenerateRRDNSKEY(zName, dConf.Algo, dns.DNSKEYFlagSecureEntryPoint)
	zskRR, zskPriv := xperi.GenerateRRDNSKEY(zName, dConf.Algo, dns.DNSKEYFlagZoneKey)
	kSKTag := xperi.CalculateKeyTag(*kskRR.RData.(*dns.DNSRDATADNSKEY))
	zSKTag := xperi.CalculateKeyTag(*zskRR.RData.(*dns.DNSRDATADNSKEY))

	return DNSSECMaterial{
		ZSKTag: int(zSKTag),
		KSKTag: int(kSKTag),

		ZSKRecord: zskRR,
		KSKRecord: kskRR,

		ZSKPriv: zskPriv,
		KSKPriv: kskPriv,
	}
}

// GetDNSSECMaterial 获取指定区域的 DNSSEC 材料
// 如果该区域的 DNSSEC 材料不存在，则会根据 DNSSEC 配置生成一个
func GetDNSSECMaterial(zName string, dMap *sync.Map, dConf DNSSECConfig) DNSSECMaterial {
	// 从映射中获取 DNSSEC 材料
	if dMat, ok := dMap.Load(zName); ok {
		return dMat.(DNSSECMaterial)
	} else {
		c := CreateDNSSECMaterial(dConf, zName)
		// 将生成的 DNSSEC 材料存储到映射中
		dMap.Store(zName, c)
		return c
	}
}

// EstablishCoT 根据查询自动添加 DNSKEY，DS，RRSIG 记录
// 自动完成信任链（Trust of Chain）的建立。
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - dConf DNSSECConfig，DNSSEC 配置
//   - dMap map[string]DNSSECMaterial，区域名与其相应 DNSSEC 材料的映射
//   - resp *dns.DNSMessage，回复信息
func EstablishCoT(qry dns.DNSMessage, resp *dns.DNSMessage, dConf DNSSECConfig, dMap *sync.Map) error {
	// 提取查询类型和查询名称
	qType := qry.Question[0].Type
	qName := strings.ToLower(qry.Question[0].Name.DomainName)
	rrset := []dns.DNSResourceRecord{}

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，
		dMat := GetDNSSECMaterial(qName, dMap, dConf)
		rrset = append(rrset, dMat.ZSKRecord, dMat.KSKRecord)
		resp.Answer = append(resp.Answer, dMat.ZSKRecord, dMat.KSKRecord)

		// 生成密钥集签名
		sig := SignSet(rrset, CryptoMaterial{})

		rrset = append(rrset, sig)
		resp.Answer = append(resp.Answer, rrset...)

		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dMat := GetDNSSECMaterial(qName, dMap, dConf)
		// 生成正确DS记录
		kskRData, _ := dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY)
		ds := xperi.GenerateRRDS(qName, *kskRData, dConf.Type)
		rrset = append(rrset, ds)

		upName := dns.GetUpperDomainName(&qName)
		dMat = GetDNSSECMaterial(upName, dMap, dConf)
		// 签名
		sig := SignSet(rrset, CryptoMaterial{})
		rrset = append(rrset, sig)
		resp.Answer = append(resp.Answer, sig)
	}
	FixCount(resp)
	return nil
}

func InitTruncatedResponse(qry []byte) []byte {
	resp := make([]byte, len(qry))
	copy(resp, qry)
	resp[2] |= 0x86 // 设置QR, TC, AA位为1
	return resp
}
