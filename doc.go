// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// GoDNS 是一个快速、灵活的实验用 DNS 服务器，旨在帮助开发者和研究人员探索和实验 DNS 协议的各种特性。
//
// # GoDNSServer
//
// GoDNSServer 是对 DNS 服务器的最顶层封装。
//
// GoDNSServer 包含以下三部分：
//   - ServerConfig: DNS 服务器配置
//   - Sniffer: 数据包嗅探器
//   - Handler: 数据包处理器
//     }
//
// Sniffer 用于监听指定的网络设备和端口，嗅探 DNS 请求。
// Handler 用于处理 DNS 请求，并生成回复。
//
// ## 示例
//
//	 通过下述几行代码，可以一键启动一个基础的 GoDNS 服务器：
//	 // 创建一个 DNS 服务器
//		server := &GoDNSServer{
//			ServerConfig: serverConf,
//			Sniffer: []*Sniffer{
//				NewSniffer(SnifferConfig{
//					Device:   serverConf.NetworkDevice,
//					Port:     serverConf.Port,
//					PktMax:   65535,
//					Protocol: ProtocolUDP,
//				}),
//			},
//			Handler: NewHandler(serverConf, &DullResponser{}),
//		}
//		server.Start()
//
// ## 构造、生成 DNS 回复
//
// Handler用于响应、处理 DNS 请求并回复
// 其包含以下四部分：
//   - Parser 解析DNS请求 [parser.go]
//   - Responser 生成DNS回复 [responser.go]
//   - Sender 发送DNS回复 [sender.go]
//   - DNSServerConfig 记录DNS服务器配置
//
// Responser 接口的 Response 方法用于生成 DNS 回复。
// 通过实现 Responser 接口，可以自定义 DNS 回复的生成方式。
// [responser.go]文件中提供了若干的 Responser 实现示例，
// 可以参考它们的实现方式来实现自定义的 Responser，
// 从而随意构造 DNS 回复。
//
// # dns包
//
// dns包使用go的内置函数提供了对 DNS 消息的编解码实现。
//
// DNSMessage 是表示 DNS消息 的最顶层封装。
//
// // DNSMessage 表示 DNS协议 的消息结构。
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
// dns 包对 DNS 消息的格式没有强制限制，
// 并且支持对 未知类型的资源记录 进行编解码，
// 这使得其可以随意构造和解析 DNS 消息，来满足实验需求。
//
// ## xlayers 子包
//
// xlayers 包提供了实现 gopacket.Layer 接口的 DNS 封装结构。
//
// [xlayers.go]文件提供的 DNS 结构体可用于替换 gopacket.Layer 中原有的 DNS 结构体，
// 使 gopacket 使用dns包中的实现进行 DNS 消息的编解码。
//
//	 // DNS 结构体用于替换 gopacket.Layer 中原有的 DNS 结构体，
//		type DNS struct {
//			layers.BaseLayer
//			DNSMessage dns.DNSMessage
//		}
//
// ## xperi 子包
//
// xperi 包实现了一些实验用函数。
//
// 其中 dnssec.go 文件提供了一系列 DNSSEC 相关实验辅助函数。
//   - ParseKeyBase64 用于解析 Base64 编码的 DNSKEY 为字节形式。
//   - CalculateKeyTag 用于计算 DNSKEY 的 Key Tag。
//   - GenerateDNSKEY 根据参数生成 DNSKEY RDATA。
//   - GenerateRRSIG 根据参数对RRSET进行签名，生成 RRSIG RDATA。
//   - GenerateDS 根据参数生成 DNSKEY 的 DS RDATA。
//   - GenRandomRRSIG 用于生成一个随机的 RRSIG RDATA。
//   - GenWrongKeyWithTag 用于生成错误的，但具有指定 KeyTag 的 DNSKEY RDATA。
//   - GenKeyWithTag [该函数十分耗时] 用于生成一个具有指定 KeyTag 的 DNSKEY。
package godns
