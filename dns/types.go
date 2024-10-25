// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// 该文件定义了 DNS 协议中的一些类型。
package dns

// DNSClass 表示DNS请求的类别，不同的类别对应不同的网络名称空间。
type DNSClass uint16

// DNSClass常用的类别
const (
	DNSClassIN  DNSClass = 1   // Internet [RFC1035]
	DNSClassCS  DNSClass = 2   // CSNET [Dyer 87]
	DNSClassCH  DNSClass = 3   // Chaos [Moon 87]
	DNSClassHS  DNSClass = 4   // Hesiod [Dyer 87]
	DNSClassANY DNSClass = 255 // 任意类别
)

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
		return "UNKNOWN"
	}
}

// DNSResponseCode 表示DNS恢复响应码，用于指示DNS服务器对查询的响应结果。
type DNSResponseCode uint8

// DNS回复常用的响应码
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

func (drc DNSResponseCode) String() string {
	switch drc {
	default:
		return "Unknown"
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

// DNSRRType 表示DNS资源记录的类型。
type DNSRRType uint16

// 目前已知的DNS资源记录类型（大部分仍未实现）
const (
	DNSRRTypeA          DNSRRType = 1     // 主机地址 [RFC1035]
	DNSRRTypeNS         DNSRRType = 2     // 权威名称服务器 [RFC1035]
	DNSRRTypeMD         DNSRRType = 3     // 邮件目的地（过时 - 使用MX） [RFC1035]
	DNSRRTypeMF         DNSRRType = 4     // 邮件转发器（过时 - 使用MX） [RFC1035]
	DNSRRTypeCNAME      DNSRRType = 5     // 别名的规范名称 [RFC1035]
	DNSRRTypeSOA        DNSRRType = 6     // 标记权威区域的开始 [RFC1035]
	DNSRRTypeMB         DNSRRType = 7     // 邮箱域名（实验性） [RFC1035]
	DNSRRTypeMG         DNSRRType = 8     // 邮件组成员（实验性） [RFC1035]
	DNSRRTypeMR         DNSRRType = 9     // 邮件重命名域名（实验性） [RFC1035]
	DNSRRTypeNULL       DNSRRType = 10    // 空记录（实验性） [RFC1035]
	DNSRRTypeWKS        DNSRRType = 11    // 知名服务描述 [RFC1035]
	DNSRRTypePTR        DNSRRType = 12    // 域名指针 [RFC1035]
	DNSRRTypeHINFO      DNSRRType = 13    // 主机信息 [RFC1035]
	DNSRRTypeMINFO      DNSRRType = 14    // 邮箱或邮件列表信息 [RFC1035]
	DNSRRTypeMX         DNSRRType = 15    // 邮件交换 [RFC1035]
	DNSRRTypeTXT        DNSRRType = 16    // 文本字符串 [RFC1035]
	DNSRRTypeRP         DNSRRType = 17    // 负责人员 [RFC1183]
	DNSRRTypeAFSDB      DNSRRType = 18    // AFS数据存储位置 [RFC1183]
	DNSRRTypeX25        DNSRRType = 19    // X.25 PSDN地址 [RFC1183]
	DNSRRTypeISDN       DNSRRType = 20    // ISDN地址 [RFC1183]
	DNSRRTypeRT         DNSRRType = 21    // 路由通过 [RFC1183]
	DNSRRTypeNSAP       DNSRRType = 22    // NSAP地址，NSAP风格A记录 [RFC1706][RFC1348]
	DNSRRTypeNSAPPTR    DNSRRType = 23    // 域名指针，NSAP风格 [RFC1348]
	DNSRRTypeSIG        DNSRRType = 24    // 安全签名 [RFC2535]
	DNSRRTypeKEY        DNSRRType = 25    // 安全密钥 [RFC2535]
	DNSRRTypePX         DNSRRType = 26    // X.400邮件映射信息 [RFC2163]
	DNSRRTypeGPOS       DNSRRType = 27    // 地理位置 [RFC1712]
	DNSRRTypeAAAA       DNSRRType = 28    // IP6地址 [RFC3596]
	DNSRRTypeLOC        DNSRRType = 29    // 位置信息 [RFC1876]
	DNSRRTypeNXT        DNSRRType = 30    // 下一个域（过时） [RFC2535]
	DNSRRTypeEID        DNSRRType = 31    // 端点标识符 [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
	DNSRRTypeNIMLOC     DNSRRType = 32    // Nimrod定位器 [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
	DNSRRTypeSRV        DNSRRType = 33    // 服务器选择 [RFC2782]
	DNSRRTypeATMA       DNSRRType = 34    // ATM地址 [ATM论坛技术委员会，“ATM名称系统，V2.0”，文档ID：AF-DANS-0152.000]
	DNSRRTypeNAPTR      DNSRRType = 35    // 命名权威指针 [RFC2915][RFC2168][RFC3403]
	DNSRRTypeKX         DNSRRType = 36    // 密钥交换者 [RFC2230]
	DNSRRTypeCERT       DNSRRType = 37    // 证书 [RFC4398]
	DNSRRTypeA6         DNSRRType = 38    // A6（过时 - 使用AAAA） [RFC3226][RFC2874][RFC6563]
	DNSRRTypeDNAME      DNSRRType = 39    // DNAME [RFC6672]
	DNSRRTypeSINK       DNSRRType = 40    // SINK [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink]
	DNSRRTypeOPT        DNSRRType = 41    // OPT [RFC6891][RFC3225]
	DNSRRTypeAPL        DNSRRType = 42    // APL [RFC3123]
	DNSRRTypeDS         DNSRRType = 43    // 委托签名者 [RFC4034][RFC3658]
	DNSRRTypeSSHFP      DNSRRType = 44    // SSH密钥指纹 [RFC4255]
	DNSRRTypeIPSECKEY   DNSRRType = 45    // IPSECKEY [RFC4025]
	DNSRRTypeRRSIG      DNSRRType = 46    // RRSIG [RFC4034][RFC3755]
	DNSRRTypeNSEC       DNSRRType = 47    // NSEC [RFC4034][RFC3755]
	DNSRRTypeDNSKEY     DNSRRType = 48    // DNSKEY [RFC4034][RFC3755]
	DNSRRTypeDHCID      DNSRRType = 49    // DHCID [RFC4701]
	DNSRRTypeNSEC3      DNSRRType = 50    // NSEC3 [RFC5155]
	DNSRRTypeNSEC3PARAM DNSRRType = 51    // NSEC3PARAM [RFC5155]
	DNSRRTypeTLSA       DNSRRType = 52    // TLSA [RFC6698]
	DNSRRTypeSMIMEA     DNSRRType = 53    // S/MIME证书关联 [RFC8162]
	DNSRRTypeHIP        DNSRRType = 55    // 主机身份协议 [RFC5205]
	DNSRRTypeNINFO      DNSRRType = 56    // NINFO [Jim_Reid]
	DNSRRTypeRKEY       DNSRRType = 57    // RKEY [Jim_Reid]
	DNSRRTypeTALINK     DNSRRType = 58    // 信任锚链接 [Wouter_Wijngaards]
	DNSRRTypeCDS        DNSRRType = 59    // 子DS [RFC7344]
	DNSRRTypeCDNSKEY    DNSRRType = 60    // 子域希望反射的DNSKEY [RFC7344]
	DNSRRTypeOPENPGPKEY DNSRRType = 61    // OpenPGP密钥 [RFC7929]
	DNSRRTypeCSYNC      DNSRRType = 62    // 子到父同步 [RFC7477]
	DNSRRTypeZONEMD     DNSRRType = 63    // DNS区域的消息摘要 [draft-wessels-dns-zone-digest]
	DNSRRTypeSVCB       DNSRRType = 64    // SVCB [draft-ietf-dnsop-svcb-https]
	DNSRRTypeHTTPS      DNSRRType = 65    // HTTPS [draft-ietf-dnsop-svcb-https]
	DNSRRTypeSPF        DNSRRType = 99    // SPF [RFC7208]
	DNSRRTypeUINFO      DNSRRType = 100   // UINFO [IANA-保留]
	DNSRRTypeUID        DNSRRType = 101   // UID [IANA-保留]
	DNSRRTypeGID        DNSRRType = 102   // GID [IANA-保留]
	DNSRRTypeUNSPEC     DNSRRType = 103   // UNSPEC [IANA-保留]
	DNSRRTypeNID        DNSRRType = 104   // NID [RFC6742]
	DNSRRTypeL32        DNSRRType = 105   // L32 [RFC6742]
	DNSRRTypeL64        DNSRRType = 106   // L64 [RFC6742]
	DNSRRTypeLP         DNSRRType = 107   // LP [RFC6742]
	DNSRRTypeEUI48      DNSRRType = 108   // EUI-48 [RFC7043]
	DNSRRTypeEUI64      DNSRRType = 109   // EUI-64 [RFC7043]
	DNSRRTypeTKEY       DNSRRType = 249   // 事务密钥 [RFC2930]
	DNSRRTypeTSIG       DNSRRType = 250   // 事务签名 [RFC2845]
	DNSRRTypeIXFR       DNSRRType = 251   // 增量传输 [RFC1995]
	DNSRRTypeAXFR       DNSRRType = 252   // 整个区域的传输 [RFC1035]
	DNSRRTypeMAILB      DNSRRType = 253   // 请求邮箱相关记录（MB、MG或MR） [RFC1035]
	DNSRRTypeMAILA      DNSRRType = 254   // 请求邮件代理RR（过时 - 请参见MX） [RFC1035]
	DNSRRTypeURI        DNSRRType = 256   // URI [RFC7553]
	DNSRRTypeCAA        DNSRRType = 257   // 认证机构限制 [RFC6844]
	DNSRRTypeAVC        DNSRRType = 258   // 应用可见性和控制 [RFC6195]
	DNSRRTypeDOA        DNSRRType = 259   // 数字对象架构 [RFC7208]
	DNSRRTypeAMTRELAY   DNSRRType = 260   // 自动多播隧道中继 [RFC8777]
	DNSRRTypeTA         DNSRRType = 32768 // DNS信任机构 [Weiler]（私有使用）
	DNSRRTypeDLV        DNSRRType = 32769 // DNSSEC旁路验证 [RFC4431]
)

func (rrType DNSRRType) String() string {
	switch rrType {
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
	case DNSRRTypeAXFR:
		return "AXFR"
	case DNSRRTypeMAILB:
		return "MAILB"
	case DNSRRTypeMAILA:
		return "MAILA"
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
	default:
		return "UNKNOWN"
	}
}
