// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// types.go 文件定义了dns包所使用到的 DNS 协议字段类型。

package dns

import "fmt"

// DNSClass 表示DNS请求的类别，不同的类别对应不同的网络名称空间。
type DNSClass uint16

// DNSClass的常用类别

const (
	DNSClassIN  DNSClass = 1   // Internet [RFC1035]
	DNSClassCS  DNSClass = 2   // CSNET [Dyer 87]
	DNSClassCH  DNSClass = 3   // Chaos [Moon 87]
	DNSClassHS  DNSClass = 4   // Hesiod [Dyer 87]
	DNSClassANY DNSClass = 255 // 任意类别
)

// String 方法返回 DNS 类别的字符串表示。
func (dnsClass DNSClass) String() string {
	switch dnsClass {
	case DNSClassIN:
		return "IN"
	case DNSClassCS:
		return "CS"
	case DNSClassCH:
		return "CH"
	case DNSClassHS:
		return "HS"
	case DNSClassANY:
		return "ANY"
	default:
		return fmt.Sprintf("Unknown DNS Class: (%d)", dnsClass)
	}
}

// DNSResponseCode 表示DNS恢复响应码，用于指示DNS服务器对查询的响应结果。
type DNSResponseCode uint8

// DNS回复的响应码

const (
	DNSResponseCodeNoErr     DNSResponseCode = 0  // 无错误							[RFC1035]
	DNSResponseCodeFormErr   DNSResponseCode = 1  // 格式错误                		[RFC1035]
	DNSResponseCodeServFail  DNSResponseCode = 2  // 服务器失败                 	[RFC1035]
	DNSResponseCodeNXDomain  DNSResponseCode = 3  // 不存在的域名                   [RFC1035]
	DNSResponseCodeNotImp    DNSResponseCode = 4  // 未实现                         [RFC1035]
	DNSResponseCodeRefused   DNSResponseCode = 5  // 查询被拒绝                     [RFC1035]
	DNSResponseCodeYXDomain  DNSResponseCode = 6  // 名称不应存在                   [RFC2136]
	DNSResponseCodeYXRRSet   DNSResponseCode = 7  // RR集不应存在                   [RFC2136]
	DNSResponseCodeNXRRSet   DNSResponseCode = 8  // RR集应存在但不存在             [RFC2136]
	DNSResponseCodeNotAuth   DNSResponseCode = 9  // 服务器对区域无权威性           [RFC2136]
	DNSResponseCodeNotZone   DNSResponseCode = 10 // 名称不在区域中                 [RFC2136]
	DNSResponseCodeBadVers   DNSResponseCode = 16 // 错误的OPT版本                  [RFC2671]
	DNSResponseCodeBadSig    DNSResponseCode = 16 // TSIG签名失败                   [RFC2845]
	DNSResponseCodeBadKey    DNSResponseCode = 17 // 未识别的密钥                   [RFC2845]
	DNSResponseCodeBadTime   DNSResponseCode = 18 // 签名超出时间窗口               [RFC2845]
	DNSResponseCodeBadMode   DNSResponseCode = 19 // 错误的TKEY模式                 [RFC2930]
	DNSResponseCodeBadName   DNSResponseCode = 20 // 重复的密钥名称                 [RFC2930]
	DNSResponseCodeBadAlg    DNSResponseCode = 21 // 不支持的算法                   [RFC2930]
	DNSResponseCodeBadTruc   DNSResponseCode = 22 // 错误的截断                     [RFC4635]
	DNSResponseCodeBadCookie DNSResponseCode = 23 // 错误/缺失的服务器Cookie        [RFC7873]
)

// DNSOpCode 表示DNS操作码，用于指示DNS请求的操作类型。
type DNSOpCode uint8

// DNSOpCode常用的操作码
const (
	DNSOpCodeQuery  DNSOpCode = 0 // 标准查询
	DNSOpCodeIQuery DNSOpCode = 1 // 反向查询
	DNSOpCodeStatus DNSOpCode = 2 // 服务器状态请求
	DNSOpCodeNotify DNSOpCode = 4 // 通知
	DNSOpCodeUpdate DNSOpCode = 5 // 更新
)

// DNSType 表示 DNS资源记录 中的 TYPE 字段及 DNS问题 中的 QTYPE 字段。
//  - QTYPE 字段用于指示查询的资源记录类型。
//  - TYPE 字段用于指示资源记录的类型。
// QTYPE 是 TYPE 的超集，其包含了额外的查询类型。
type DNSType uint16

// 目前已知的DNS资源记录及查询类型

const (
	DNSRRTypeA          DNSType = 1     // 主机地址 [RFC1035]
	DNSRRTypeNS         DNSType = 2     // 权威名称服务器 [RFC1035]
	DNSRRTypeMD         DNSType = 3     // 邮件目的地（过时 - 使用MX） [RFC1035]
	DNSRRTypeMF         DNSType = 4     // 邮件转发器（过时 - 使用MX） [RFC1035]
	DNSRRTypeCNAME      DNSType = 5     // 别名的规范名称 [RFC1035]
	DNSRRTypeSOA        DNSType = 6     // 标记权威区域的开始 [RFC1035]
	DNSRRTypeMB         DNSType = 7     // 邮箱域名（实验性） [RFC1035]
	DNSRRTypeMG         DNSType = 8     // 邮件组成员（实验性） [RFC1035]
	DNSRRTypeMR         DNSType = 9     // 邮件重命名域名（实验性） [RFC1035]
	DNSRRTypeNULL       DNSType = 10    // 空记录（实验性） [RFC1035]
	DNSRRTypeWKS        DNSType = 11    // 知名服务描述 [RFC1035]
	DNSRRTypePTR        DNSType = 12    // 域名指针 [RFC1035]
	DNSRRTypeHINFO      DNSType = 13    // 主机信息 [RFC1035]
	DNSRRTypeMINFO      DNSType = 14    // 邮箱或邮件列表信息 [RFC1035]
	DNSRRTypeMX         DNSType = 15    // 邮件交换 [RFC1035]
	DNSRRTypeTXT        DNSType = 16    // 文本字符串 [RFC1035]
	DNSRRTypeRP         DNSType = 17    // 负责人员 [RFC1183]
	DNSRRTypeAFSDB      DNSType = 18    // AFS数据存储位置 [RFC1183]
	DNSRRTypeX25        DNSType = 19    // X.25 PSDN地址 [RFC1183]
	DNSRRTypeISDN       DNSType = 20    // ISDN地址 [RFC1183]
	DNSRRTypeRT         DNSType = 21    // 路由通过 [RFC1183]
	DNSRRTypeNSAP       DNSType = 22    // NSAP地址，NSAP风格A记录 [RFC1706][RFC1348]
	DNSRRTypeNSAPPTR    DNSType = 23    // 域名指针，NSAP风格 [RFC1348]
	DNSRRTypeSIG        DNSType = 24    // 安全签名 [RFC2535]
	DNSRRTypeKEY        DNSType = 25    // 安全密钥 [RFC2535]
	DNSRRTypePX         DNSType = 26    // X.400邮件映射信息 [RFC2163]
	DNSRRTypeGPOS       DNSType = 27    // 地理位置 [RFC1712]
	DNSRRTypeAAAA       DNSType = 28    // IP6地址 [RFC3596]
	DNSRRTypeLOC        DNSType = 29    // 位置信息 [RFC1876]
	DNSRRTypeNXT        DNSType = 30    // 下一个域（过时） [RFC2535]
	DNSRRTypeEID        DNSType = 31    // 端点标识符 [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
	DNSRRTypeNIMLOC     DNSType = 32    // Nimrod定位器 [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
	DNSRRTypeSRV        DNSType = 33    // 服务器选择 [RFC2782]
	DNSRRTypeATMA       DNSType = 34    // ATM地址 [ATM论坛技术委员会，“ATM名称系统，V2.0”，文档ID：AF-DANS-0152.000]
	DNSRRTypeNAPTR      DNSType = 35    // 命名权威指针 [RFC2915][RFC2168][RFC3403]
	DNSRRTypeKX         DNSType = 36    // 密钥交换者 [RFC2230]
	DNSRRTypeCERT       DNSType = 37    // 证书 [RFC4398]
	DNSRRTypeA6         DNSType = 38    // A6（过时 - 使用AAAA） [RFC3226][RFC2874][RFC6563]
	DNSRRTypeDNAME      DNSType = 39    // DNAME [RFC6672]
	DNSRRTypeSINK       DNSType = 40    // SINK [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]
	DNSRRTypeOPT        DNSType = 41    // OPT [RFC6891][RFC3225]
	DNSRRTypeAPL        DNSType = 42    // APL [RFC3123]
	DNSRRTypeDS         DNSType = 43    // 委托签名者 [RFC4034][RFC3658]
	DNSRRTypeSSHFP      DNSType = 44    // SSH密钥指纹 [RFC4255]
	DNSRRTypeIPSECKEY   DNSType = 45    // IPSECKEY [RFC4025]
	DNSRRTypeRRSIG      DNSType = 46    // RRSIG [RFC4034][RFC3755]
	DNSRRTypeNSEC       DNSType = 47    // NSEC [RFC4034][RFC3755]
	DNSRRTypeDNSKEY     DNSType = 48    // DNSKEY [RFC4034][RFC3755]
	DNSRRTypeDHCID      DNSType = 49    // DHCID [RFC4701]
	DNSRRTypeNSEC3      DNSType = 50    // NSEC3 [RFC5155]
	DNSRRTypeNSEC3PARAM DNSType = 51    // NSEC3PARAM [RFC5155]
	DNSRRTypeTLSA       DNSType = 52    // TLSA [RFC6698]
	DNSRRTypeSMIMEA     DNSType = 53    // S/MIME证书关联 [RFC8162]
	DNSRRTypeHIP        DNSType = 55    // 主机身份协议 [RFC5205]
	DNSRRTypeNINFO      DNSType = 56    // NINFO [Jim_Reid]
	DNSRRTypeRKEY       DNSType = 57    // RKEY [Jim_Reid]
	DNSRRTypeTALINK     DNSType = 58    // 信任锚链接 [Wouter_Wijngaards]
	DNSRRTypeCDS        DNSType = 59    // 子DS [RFC7344]
	DNSRRTypeCDNSKEY    DNSType = 60    // 子域希望反射的DNSKEY [RFC7344]
	DNSRRTypeOPENPGPKEY DNSType = 61    // OpenPGP密钥 [RFC7929]
	DNSRRTypeCSYNC      DNSType = 62    // 子到父同步 [RFC7477]
	DNSRRTypeZONEMD     DNSType = 63    // DNS区域的消息摘要 [draft-wessels-dns-zone-digest]
	DNSRRTypeSVCB       DNSType = 64    // SVCB [draft-ietf-dnsop-svcb-https]
	DNSRRTypeHTTPS      DNSType = 65    // HTTPS [draft-ietf-dnsop-svcb-https]
	DNSRRTypeSPF        DNSType = 99    // SPF [RFC7208]
	DNSRRTypeUINFO      DNSType = 100   // UINFO [IANA-保留]
	DNSRRTypeUID        DNSType = 101   // UID [IANA-保留]
	DNSRRTypeGID        DNSType = 102   // GID [IANA-保留]
	DNSRRTypeUNSPEC     DNSType = 103   // UNSPEC [IANA-保留]
	DNSRRTypeNID        DNSType = 104   // NID [RFC6742]
	DNSRRTypeL32        DNSType = 105   // L32 [RFC6742]
	DNSRRTypeL64        DNSType = 106   // L64 [RFC6742]
	DNSRRTypeLP         DNSType = 107   // LP [RFC6742]
	DNSRRTypeEUI48      DNSType = 108   // EUI-48 [RFC7043]
	DNSRRTypeEUI64      DNSType = 109   // EUI-64 [RFC7043]
	DNSRRTypeTKEY       DNSType = 249   // 事务密钥 [RFC2930]
	DNSRRTypeTSIG       DNSType = 250   // 事务签名 [RFC2845]
	DNSRRTypeIXFR       DNSType = 251   // 增量传输 [RFC1995]
	DNSQTypeAXFR        DNSType = 252   // 请求整个区域的传输 [RFC1035]
	DNSQTypeMAILB       DNSType = 253   // 请求邮箱相关记录（MB、MG或MR） [RFC1035]
	DNSQTypeMAILA       DNSType = 254   // 请求邮件代理RR（过时 - 请参见MX） [RFC1035]
	DNSQTypeANY         DNSType = 255   // 请求任意类型的资源记录 [RFC1035]
	DNSRRTypeURI        DNSType = 256   // URI [RFC7553]
	DNSRRTypeCAA        DNSType = 257   // 认证机构限制 [RFC6844]
	DNSRRTypeAVC        DNSType = 258   // 应用可见性和控制 [RFC6195]
	DNSRRTypeDOA        DNSType = 259   // 数字对象架构 [RFC7208]
	DNSRRTypeAMTRELAY   DNSType = 260   // 自动多播隧道中继 [RFC8777]
	DNSRRTypeTA         DNSType = 32768 // DNS信任机构 [Weiler]（私有使用）
	DNSRRTypeDLV        DNSType = 32769 // DNSSEC旁路验证 [RFC4431]

	DNSRRTypeUnknown DNSType = 0 // 未知类型
)

// DNSSECAlgorithm 表示DNSSEC记录所使用的签名算法。
// 更多信息请参阅 RFC 4034 第 5.1 节。
type DNSSECAlgorithm uint8

// DNSSEC已知的签名算法 RFC 4034 Appendix A.1.
const (
	DNSSECAlgorithmReserved        DNSSECAlgorithm = 0
	DNSSECAlgorithmRSAMD5          DNSSECAlgorithm = 1 // Zone Signing: n, [RFC2537], NOT RECOMMENDED
	DNSSECAlgorithmDH              DNSSECAlgorithm = 2 // Zone Signing: n, [RFC2539]
	DNSSECAlgorithmDSASHA1         DNSSECAlgorithm = 3 // [RFC2536]
	DNSSECAlgorithmECC             DNSSECAlgorithm = 4
	DNSSECAlgorithmRSASHA1         DNSSECAlgorithm = 5 // [RFC3110]
	DNSSECAlgorithmDSASHA1NSEC3    DNSSECAlgorithm = 6
	DNSSECAlgorithmRSASHA1NSEC3    DNSSECAlgorithm = 7
	DNSSECAlgorithmRSASHA256       DNSSECAlgorithm = 8
	DNSSECAlgorithmRSASHA512       DNSSECAlgorithm = 10
	DNSSECAlgorithmECCGOST         DNSSECAlgorithm = 12
	DNSSECAlgorithmECDSAP256SHA256 DNSSECAlgorithm = 13
	DNSSECAlgorithmECDSAP384SHA384 DNSSECAlgorithm = 14
	DNSSECAlgorithmED25519         DNSSECAlgorithm = 15
	DNSSECAlgorithmED448           DNSSECAlgorithm = 16
	DNSSECAlgorithmINDIRECT        DNSSECAlgorithm = 252
	DNSSECAlgorithmPRIVATEDNS      DNSSECAlgorithm = 253 // Private DNS [RFC4034 Appendix A.1.1.]
	DNSSECAlgorithmPRIVATEOID      DNSSECAlgorithm = 254 // Private OID [RFC4034 Appendix A.1.1.]
	DNSSECAlgorithmReserved255     DNSSECAlgorithm = 255
)

// DNSKEYFlag 表示DNSKEY记录的密钥标志字段。
// 更多信息请参阅 RFC 4034 第 2.1.1 节。
type DNSKEYFlag uint16

// DNSSEC已定义的密钥标志
const (
	// DNSKEYFlagOtherKey 表示其他密钥
	DNSKEYFlagOtherKey DNSKEYFlag = 0
	// DNSKEYFlagZoneKey 256 表示区域密钥 ZSK (Zone Signing Key)
	DNSKEYFlagZoneKey DNSKEYFlag = 256
	// DNSKEYFlagSecureEntryPoint 257 表示KSK (Key Signing Key) (Secure Entry Point)
	DNSKEYFlagSecureEntryPoint DNSKEYFlag = 257
)

// DNSKEYProtocol 表示DNSKEY记录的密钥协议字段。
// 更多信息请参阅 RFC 4034 第 2.1.2 节。
type DNSKEYProtocol uint8

// DNSKEYProtocol 已定义的密钥协议
// 3为协议默认值，0为保留值
const (
	DNSKEYProtocolReserved DNSKEYProtocol = 0
	DNSKEYProtocolValue    DNSKEYProtocol = 3
)

// DNSSECDigestType 表示DNSSEC记录的摘要类型。
type DNSSECDigestType uint8

// DNSSEC已定义的摘要类型 [RFC4034 Appendix A.2.]
const (
	DNSSECDigestTypeReserved DNSSECDigestType = 0
	DNSSECDigestTypeSHA1     DNSSECDigestType = 1
	DNSSECDigestTypeSHA256   DNSSECDigestType = 2
	DNSSECDigestTypeGOST     DNSSECDigestType = 3
	DNSSECDigestTypeSHA384   DNSSECDigestType = 4
	DNSSECDigestTypeSHA512   DNSSECDigestType = 5
)

// String 方法返回 DNS 响应码的字符串表示。
func (drc DNSResponseCode) String() string {
	switch drc {
	default:
		return fmt.Sprintf("Unknown DNS Response Code: (%d)", drc)
	case DNSResponseCodeNoErr:
		return "No Error"
	case DNSResponseCodeFormErr:
		return "Format Error"
	case DNSResponseCodeServFail:
		return "Server Failure"
	case DNSResponseCodeNXDomain:
		return "Non-Existent Domain"
	case DNSResponseCodeNotImp:
		return "Not Implemented"
	case DNSResponseCodeRefused:
		return "Query Refused"
	case DNSResponseCodeYXDomain:
		return "Name Exists when it should not"
	case DNSResponseCodeYXRRSet:
		return "RR Set Exists when it should not"
	case DNSResponseCodeNXRRSet:
		return "RR Set that should exist does not"
	case DNSResponseCodeNotAuth:
		return "Server Not Authoritative for zone"
	case DNSResponseCodeNotZone:
		return "Name not contained in zone"
	case DNSResponseCodeBadVers:
		return "Bad OPT Version"
	case DNSResponseCodeBadKey:
		return "Key not recognized"
	case DNSResponseCodeBadTime:
		return "Signature out of time window"
	case DNSResponseCodeBadMode:
		return "Bad TKEY Mode"
	case DNSResponseCodeBadName:
		return "Duplicate key name"
	case DNSResponseCodeBadAlg:
		return "Algorithm not supported"
	case DNSResponseCodeBadTruc:
		return "Bad Truncation"
	case DNSResponseCodeBadCookie:
		return "Bad Cookie"
	}
}

// String 方法返回 DNS 资源记录类型的字符串表示。
func (dnsType DNSType) String() string {
	switch dnsType {
	default:
		return fmt.Sprintf("Unknown DNS RR Type: (%d)", dnsType)
	case DNSRRTypeA:
		return "A"
	case DNSRRTypeNS:
		return "NS"
	case DNSRRTypeMD:
		return "MD"
	case DNSRRTypeMF:
		return "MF"
	case DNSRRTypeCNAME:
		return "CNAME"
	case DNSRRTypeSOA:
		return "SOA"
	case DNSRRTypeMB:
		return "MB"
	case DNSRRTypeMG:
		return "MG"
	case DNSRRTypeMR:
		return "MR"
	case DNSRRTypeNULL:
		return "NULL"
	case DNSRRTypeWKS:
		return "WKS"
	case DNSRRTypePTR:
		return "PTR"
	case DNSRRTypeHINFO:
		return "HINFO"
	case DNSRRTypeMINFO:
		return "MINFO"
	case DNSRRTypeMX:
		return "MX"
	case DNSRRTypeTXT:
		return "TXT"
	case DNSRRTypeRP:
		return "RP"
	case DNSRRTypeAFSDB:
		return "AFSDB"
	case DNSRRTypeX25:
		return "X25"
	case DNSRRTypeISDN:
		return "ISDN"
	case DNSRRTypeRT:
		return "RT"
	case DNSRRTypeNSAP:
		return "NSAP"
	case DNSRRTypeNSAPPTR:
		return "NSAPPTR"
	case DNSRRTypeSIG:
		return "SIG"
	case DNSRRTypeKEY:
		return "KEY"
	case DNSRRTypePX:
		return "PX"
	case DNSRRTypeGPOS:
		return "GPOS"
	case DNSRRTypeAAAA:
		return "AAAA"
	case DNSRRTypeLOC:
		return "LOC"
	case DNSRRTypeNXT:
		return "NXT"
	case DNSRRTypeEID:
		return "EID"
	case DNSRRTypeNIMLOC:
		return "NIMLOC"
	case DNSRRTypeSRV:
		return "SRV"
	case DNSRRTypeATMA:
		return "ATMA"
	case DNSRRTypeNAPTR:
		return "NAPTR"
	case DNSRRTypeKX:
		return "KX"
	case DNSRRTypeCERT:
		return "CERT"
	case DNSRRTypeA6:
		return "A6"
	case DNSRRTypeDNAME:
		return "DNAME"
	case DNSRRTypeSINK:
		return "SINK"
	case DNSRRTypeOPT:
		return "OPT"
	case DNSRRTypeAPL:
		return "APL"
	case DNSRRTypeDS:
		return "DS"
	case DNSRRTypeSSHFP:
		return "SSHFP"
	case DNSRRTypeIPSECKEY:
		return "IPSECKEY"
	case DNSRRTypeRRSIG:
		return "RRSIG"
	case DNSRRTypeNSEC:
		return "NSEC"
	case DNSRRTypeDNSKEY:
		return "DNSKEY"
	case DNSRRTypeDHCID:
		return "DHCID"
	case DNSRRTypeNSEC3:
		return "NSEC3"
	case DNSRRTypeNSEC3PARAM:
		return "NSEC3PARAM"
	case DNSRRTypeTLSA:
		return "TLSA"
	case DNSRRTypeSMIMEA:
		return "SMIMEA"
	case DNSRRTypeHIP:
		return "HIP"
	case DNSRRTypeNINFO:
		return "NINFO"
	case DNSRRTypeRKEY:
		return "RKEY"
	case DNSRRTypeTALINK:
		return "TALINK"
	case DNSRRTypeCDS:
		return "CDS"
	case DNSRRTypeCDNSKEY:
		return "CDNSKEY"
	case DNSRRTypeOPENPGPKEY:
		return "OPENPGPKEY"
	case DNSRRTypeCSYNC:
		return "CSYNC"
	case DNSRRTypeZONEMD:
		return "ZONEMD"
	case DNSRRTypeSVCB:
		return "SVCB"
	case DNSRRTypeHTTPS:
		return "HTTPS"
	case DNSRRTypeSPF:
		return "SPF"
	case DNSRRTypeUINFO:
		return "UINFO"
	case DNSRRTypeUID:
		return "UID"
	case DNSRRTypeGID:
		return "GID"
	case DNSRRTypeUNSPEC:
		return "UNSPEC"
	case DNSRRTypeNID:
		return "NID"
	case DNSRRTypeL32:
		return "L32"
	case DNSRRTypeL64:
		return "L64"
	case DNSRRTypeLP:
		return "LP"
	case DNSRRTypeEUI48:
		return "EUI48"
	case DNSRRTypeEUI64:
		return "EUI64"
	case DNSRRTypeTKEY:
		return "TKEY"
	case DNSRRTypeTSIG:
		return "TSIG"
	case DNSRRTypeIXFR:
		return "IXFR"
	case DNSQTypeAXFR:
		return "AXFR"
	case DNSQTypeMAILB:
		return "MAILB"
	case DNSQTypeMAILA:
		return "MAILA"
	case DNSQTypeANY:
		return "ANY"
	case DNSRRTypeURI:
		return "URI"
	case DNSRRTypeCAA:
		return "CAA"
	case DNSRRTypeAVC:
		return "AVC"
	case DNSRRTypeDOA:
		return "DOA"
	case DNSRRTypeAMTRELAY:
		return "AMTRELAY"
	case DNSRRTypeTA:
		return "TA"
	case DNSRRTypeDLV:
		return "DLV"
	}
}
