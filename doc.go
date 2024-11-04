// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// GoDNS 是一个快速、灵活的实验用 DNS 服务器。
//
// # 公开版本1.0.0 ✨
// ## GoDNSServer设计完成
// DNS服务器实现
// - server.go   顶层封装
//   - sniffer.go   **监听**数据包
//   - handler.go   **处理**数据包
//     - parser.go   **解析**数据包
//     - responser.go   **生成**DNS回复
//     - sender.go    **发送**DNS回复
// ## dns包设计完成
// DNS消息编解码实现
// ```
// // DNSMessage 表示 DNS协议 的消息结构。
// type DNSMessage struct {
// 	// DNS消息 头部
// 	Header DNSHeader // DNS 头部（Header）
// 	// DNS消息的各个部分（Section）
// 	Question   DNSQuestionSection // DNS 查询部分（Questions Section）
// 	Answer     DNSResponseSection // DNS 回答部分（Answers Section）
// 	Authority  DNSResponseSection // DNS 权威部分（Authority Section）
// 	Additional DNSResponseSection // DNS 附加部分（Additional Section）
// }
// ```
// ### 子包 xlayers
// 提供实现gopacket接口的DNS封装结构
// ### 现已支持未知类型（RRType）的资源记录编解码
// 目前支持的资源记录类型有：
// 1. A 记录
// 2. CNAME 记录
// 3. MX 记录
// 4. 仍待更新...
// ## 进一步完善及测试进行中...

// **Full Changelog**: https://github.com/TochusC/godns/compare/v0.0.3...v0.1.0
//
// 其具有以下亮点🌟（尚未实现）：
//   - DNSSEC 支持
//   - 超大数据包构造
//   - 无限制的任意构造DNS消息
package godns
