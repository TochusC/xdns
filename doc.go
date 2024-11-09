// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// # 简体中文
//
// GoDNS 是一个快速、灵活的实验用 DNS 服务器，旨在帮助开发者和研究人员探索和实验 DNS 协议的各种特性。
//
// # GoDNSServer
//
// [GoDNSServer] 是对 DNS 服务器的最顶层封装。
//
// GoDNSServer 包含以下三部分：
//   - ServerConfig: DNS 服务器配置
//   - Netter: 数据包处理器
//   - Responser: DNS回复器
//
// [Netter] 接收、解析、发送数据包，并维护连接状态。
//
// [Responser] 响应、解析、构造DNS回复。
//
// 示例
//
//	通过下述几行代码，可以一键启动一个基础的 GoDNS 服务器：
//
//	server := godns.GoDNSServer{
//		ServerConfig: sConf,
//		Netter: godns.Netter{
//			Config: godns.NetterConfig{
//			Port: sConf.Port,
//				MTU:  sConf.MTU,
//			},
//		},
//		Responer: &DullResponser{
//			ServerConf: sConf,
//		},
//	}
//	server.Start()
//
// # 构造、生成 DNS 回复
//
// [Responser]用于响应、解析、构造 DNS 回复
//
//	// Responser 是一个 DNS 回复器接口。
//	// 实现该接口的结构体将根据 DNS 查询信息生成 DNS 回复信息。
//	type Responser interface {
//		// Response 根据 DNS 查询信息生成 DNS 回复信息。
//		// 其参数为：
//		//   - qInfo QueryInfo，DNS 查询信息
//		// 返回值为：
//		//   - ResponseInfo，DNS 回复信息
//		//   - error，错误信息
//		Response(ConnectionInfo) (dns.DNSMessage, error)
//	}
//
// 通过实现 Responser 接口，可以自定义 DNS 回复的生成方式。
// [responser.go]文件中提供了若干的 Responser 实现示例，
// 及许多辅助函数，如 “笨笨”处理器、[DNSSECResponser]、
// [ParseQueryInfo]、[ParseResponseInfo] 等。
//
// 可以参考它们的实现方式来实现自定义的 Responser，
// 从而随意构造 DNS 回复，实现更加复杂的回复逻辑。
//
// # dns 包
//
// dns 使用Go的内置实现，提供了 DNS消息 的编解码功能，可以用于任意构造和解析 DNS消息。
//
// [dns.DNSMessage] 表示 DNS协议 的消息结构。
//
//	type DNSMessage struct {
//		// DNS消息 头部
//		Header DNSHeader // DNS 头部（Header）
//		// DNS消息的各个部分（Section）
//		Question   DNSQuestionSection // DNS 查询部分（Questions Section）
//		Answer     DNSResponseSection // DNS 回答部分（Answers Section）
//		Authority  DNSResponseSection // DNS 权威部分（Authority Section）
//		Additional DNSResponseSection // DNS 附加部分（Additional Section）
//	}
//
// dns包中的每个结构体基本都实现了以下方法：
//   - func (s *struct) DecodeFromBuffer(buffer []byte, offset int) (int, error)
//   - func (s *struct) Encode() []byte
//   - func (s *struct) EncodeToBuffer(buffer []byte) (int, error)
//   - func (s *struct) Size() int
//   - func (s *struct) String() string
//   - [少部分实现]func (s *struct) Equal(other *struct) bool
//
// 这些方法使得可以方便地对 DNS 消息进行编解码。
//
// dns包对 DNS 消息的格式没有强制限制，并且支持对 未知类型的资源记录 进行编解码，
// 这使得其可以随意构造和解析 DNS 消息，来满足实验需求。
//
// # xperi 子包
//
// xperi 包实现了一些实验用函数。
//
// 其中 dnssec.go 文件提供了一系列 DNSSEC 相关实验辅助函数。
//
//   - ParseKeyBase64 用于解析 Base64 编码的 DNSKEY 为字节形式。
//
//   - CalculateKeyTag 用于计算 DNSKEY 的 Key Tag。
//
//   - GenerateRDATADNSKEY 根据参数生成 DNSKEY RDATA。
//
//   - GenerateRDATARRSIG 根据参数对RRSET进行签名，生成 RRSIG RDATA。
//
//   - GenerateRDATADS 根据参数生成 DNSKEY 的 DS RDATA。
//
//   - GenerateRRDNSKEY 根据参数生成 DNSKEY RR。
//
//   - GenerateRRRRSIG 根据参数对RRSET进行签名，生成 RRSIG RR。
//
//   - GenerateRRDS 根据参数生成 DNSKEY 的 DS RR。
//
//   - GenRandomRRSIG 用于生成一个随机的 RRSIG RDATA。
//
//   - GenWrongKeyWithTag 用于生成错误的，但具有指定 KeyTag 的 DNSKEY RDATA。
//
//   - GenKeyWithTag [该函数十分耗时] 用于生成一个具有指定 KeyTag 的 DNSKEY。
//
// # English
//
// GoDNS is a fast and flexible experimental DNS server designed to help developers and researchers explore and experiment with various features of the DNS protocol.
//
// # GoDNSServer
//
// GoDNSServer is the top-level abstraction for a DNS server.
//
// GoDNSServer consists of the following three components:
//   - ServerConfig: DNS server configuration
//   - Netter: Packet handler
//   - Responser: DNS responder
//
// [Netter] receives, parses, and sends packets while maintaining connection states.
//
// [Responser] responds to, parses, and constructs DNS replies.
//
// # Example
//
// You can quickly start a basic GoDNS server with the following lines of code:
//
//	server := godns.GoDNSServer{
//		ServerConfig: sConf,
//		Netter: godns.Netter{
//			Config: godns.NetterConfig{
//				Port: sConf.Port,
//				MTU:  sConf.MTU,
//			},
//		},
//		Responser: &DullResponser{
//			ServerConf: sConf,
//		},
//	}
//	server.Start()
//
// # Constructing and Generating DNS Responses
//
// [Responser] is responsible for responding to, parsing, and constructing DNS replies.
//
//	// Responser is a DNS responder interface.
//	// Structures implementing this interface generate DNS responses based on DNS query information.
//	type Responser interface {
//		// Response generates a DNS response based on the DNS query information.
//		// The parameter is:
//		//   - qInfo QueryInfo, DNS query information
//		// The return value is:
//		//   - ResponseInfo, DNS response information
//		//   - error, an error if occurred
//		Response(ConnectionInfo) (dns.DNSMessage, error)
//	}
//
// By implementing the Responser interface, you can customize how DNS responses are generated.
// The responser.go file provides several examples of Responser implementations,
// as well as many utility functions like [ParseQueryInfo], [ParseResponseInfo], etc.
//
// You can refer to these implementations to create your own custom Responser,
// allowing you to construct DNS responses in any way you choose, and implement more complex reply logic.
//
// # dns package
//
// The dns package uses Go's built-in functions to provide DNS message encoding and decoding support.
//
// [dns.DNSMessage] is the top-level abstraction for a DNS message structure.
//
// // DNSMessage represents a DNS protocol message structure.
//
//	type DNSMessage struct {
//		// DNS message header
//		Header DNSHeader // DNS header (Header)
//		// Sections of the DNS message
//		Question   DNSQuestionSection // DNS query section (Questions Section)
//		Answer     DNSResponseSection // DNS answer section (Answers Section)
//		Authority  DNSResponseSection // DNS authority section (Authority Section)
//		Additional DNSResponseSection // DNS additional section (Additional Section)
//	}
//
// The dns package does not impose strict limitations on the DNS message format,
// and it supports encoding and decoding of unknown resource record types,
// allowing you to construct and parse DNS messages freely to meet experimental needs.
//
// # xperi subpackage
//
// The xperi package implements several experimental utility functions.
//
// The dnssec.go file provides a series of experimental functions related to DNSSEC.
//
//   - ParseKeyBase64: Parses a Base64 encoded DNSKEY into a byte array.
//
//   - CalculateKeyTag: Calculates the Key Tag for a DNSKEY.
//
//   - GenerateRDATADNSKEY: Generates the DNSKEY RDATA based on parameters.
//
//   - GenerateRDATARRSIG: Signs the RRSET and generates RRSIG RDATA.
//
//   - GenerateRDATADS: Generates the DS RDATA for a DNSKEY.
//
//   - GenerateRRDNSKEY: Generates a DNSKEY RR based on parameters.
//
//   - GenerateRRRRSIG: Signs the RRSET and generates RRSIG RR.
//
//   - GenerateRRDS: Generates the DS RR for a DNSKEY.
//
//   - GenRandomRRSIG: Generates a random RRSIG RDATA.
//
//   - GenWrongKeyWithTag: Generates an incorrect DNSKEY with a specified KeyTag.
//
//   - GenKeyWithTag [This function is resource-intensive]: Generates a DNSKEY with a specified KeyTag.
package godns
