<div align="center">
<h1> GoDNS </h1>

快速、灵活的**实验用DNS服务器**（亮点：DNSSEC，超大数据包，无限制🌟）

[![madewithlove](https://img.shields.io/badge/made_with-%E2%9D%A4-red?style=for-the-badge&labelColor=orange)](https://github.com/TochusC/godns)


## 🚧🚧🚧仍在火热施工中🚧🚧🚧

</div>

## 测试版本0.1.0 已发布✨
基本框架完工，已可运行使用 ⚡
## GoDNSServer设计完成
DNS服务器实现
- server.go   顶层封装
  - sniffer.go   **监听**数据包
  - handler.go   **处理**数据包
    - parser.go   **解析**数据包
    - responser.go   **生成**DNS回复
    - sender.go    **发送**DNS回复
## dns包设计完成
DNS消息编解码实现
```
// DNSMessage 表示 DNS协议 的消息结构。
type DNSMessage struct {
	// DNS消息 头部
	Header DNSHeader // DNS 头部（Header）
	// DNS消息的各个部分（Section）
	Question   DNSQuestionSection // DNS 查询部分（Questions Section）
	Answer     DNSResponseSection // DNS 回答部分（Answers Section）
	Authority  DNSResponseSection // DNS 权威部分（Authority Section）
	Additional DNSResponseSection // DNS 附加部分（Additional Section）
}
```
### 子包 xlayers 
提供实现gopacket接口的DNS封装结构  
### 现已支持未知类型（RRType）的资源记录编解码
目前支持的资源记录类型有：
1. A 记录
2. CNAME 记录 
3. MX 记录
4. 仍待更新...
## 进一步完善及测试进行中...

**Full Changelog**: https://github.com/TochusC/godns/compare/v0.0.3...v0.1.0



 
