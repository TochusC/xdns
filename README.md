# GoDNS

[![madewithlove](https://img.shields.io/badge/made_with-%E2%9D%A4-red?style=for-the-badge&labelColor=orange&style=flat-square)](https://github.com/TochusC/godns)
![Go Version](https://img.shields.io/github/go-mod/go-version/tochusc/godns/master?filename=go.mod&style=flat-square)
![Latest Version](https://img.shields.io/github/v/tag/tochusc/godns?label=latest&style=flat-square)
![License](https://img.shields.io/github/license/tochusc/godns?style=flat-square)
[![GoDoc](https://godoc.org/github.com/tochusc/godns?status.svg)](https://godoc.org/github.com/tochusc/godns)

[简体中文](README.md) | [English](docs/en/README.md)

GoDNS 是一个快速、灵活的**实验用** DNS 服务器，旨在帮助开发者和研究人员探索和实验 DNS 协议的各种特性。

## 目录

- [GoDNSServer](#godnsserver)
- [示例](#示例)
- [构造和生成 DNS 回复](#构造和生成-dns-回复)
- [dns 包](#dns-包)
- [xlayers 子包](#xlayers-子包)
- [xperi 子包](#xperi-子包)

## GoDNSServer

`GoDNSServer` 是对 DNS 服务器的最顶层封装, 其由三部分组成：

1. **ServerConfig**: DNS 服务器配置。
2. **Netter**: 数据包处理器：接收、解析、发送数据包，并维护连接状态。
3. **Responser**: DNS回复器：响应、解析、构造DNS回复

```go
type GoDNSServer struct {
    ServerConfig DNSServerConfig
    Netter       Netter
    Responer     Responser
}

// GoDNSServer 启动！
func (s *GoDNSServer) Start()
```

### Netter

*`Netter` 数据包监听器：接收、解析、发送数据包，并维护连接状态。*

```go
type Netter struct { // size=16 (0x10)
    Config NetterConfig
}

// Send 函数用于发送数据包
func (n *Netter) Send(connInfo ConnectionInfo, data []byte)

// Sniff 函数用于监听指定端口，并返回链接信息通道
func (n *Netter) Sniff() chan ConnectionInfo

// handleListener 函数用于处理 TCP 链接
func (n *Netter) handleListener(lstr net.Listener, connChan chan 
ConnectionInfo)

// handlePktConn 函数用于处理 数据包 链接
func (n *Netter) handlePktConn(pktConn net.PacketConn, connChan chan 
ConnectionInfo)

// handleStreamConn 函数用于处理 流式链接
func (n *Netter) handleStreamConn(conn net.Conn, connChan chan ConnectionInfo)
```
### Responser

*`Responser` DNS回复器：响应、解析、构造DNS回复。*

`Responser`是一个接口。 实现该接口的结构体将根据 DNS 查询信息生成 DNS 回复信息。
```go
type Responser interface { // size=16 (0x10)
    // Response 根据 DNS 查询信息生成 DNS 回复信息。
    // 其参数为：
    //   - qInfo QueryInfo，DNS 查询信息
    // 返回值为：
    //   - ResponseInfo，DNS 回复信息
    //   - error，错误信息
    Response(ConnectionInfo) (dns.DNSMessage, error)
}

```

## 示例

通过下述几行代码，可以一键启动一个基础的 GoDNS 服务器：

```go
// 创建一个 DNS 服务器
server := godns.GoDNSServer{
    ServerConfig: sConf,
    Netter: godns.Netter{
        Config: godns.NetterConfig{
        Port: sConf.Port,
            MTU:  sConf.MTU,
        },
    },
    Responer: &DullResponser{
        ServerConf: sConf,
    },
}
server.Start()
```

## 构造和生成 DNS 回复

通过实现 `Responser` 接口，可以自定义 DNS 回复的生成方式。

`responser.go` 文件中提供了若干的 `Responser` 实现示例及许多辅助函数，以供参考。

## dns 包

`dns` 包使用Go的内置实现，提供了 DNS消息 的编解码功能，可以用于任意构造和解析 DNS消息。

`DNSMessage`表示 DNS协议 的消息结构。
```go
type DNSMessage struct {
    // DNS消息头部
    Header DNSHeader // DNS 头部（Header）
    // DNS消息的各个部分（Section）
    Question   DNSQuestionSection // DNS 查询部分（Questions Section）
    Answer     DNSResponseSection // DNS 回答部分（Answers Section）
    Authority  DNSResponseSection // DNS 权威部分（Authority Section）
    Additional DNSResponseSection // DNS 附加部分（Additional Section）
}
```

`dns`包中的每个结构体基本都实现了以下方法：
```go
// 从缓冲区中自解码
func (s *struct) DecodeFromBuffer(buffer []byte, offset int) (int, error)

// 编码为字节流
func (s *struct) Encode() []byte

// 编码到缓冲区
func (s *struct) EncodeToBuffer(buffer []byte) (int, error)

// 获取结构体的*实际*大小
func (s *struct) Size() int

// 获取结构体的字符串表示
func (s *struct) String() string

// [部分实现]判断两个结构体是否相等
func (s *struct) Equal(other *struct) bool
```

这些方法使得可以方便地对 DNS 消息进行编解码。

`dns`包对 DNS 消息的格式没有强制限制，并且支持对 未知类型的资源记录 进行编解码，
这使得其可以随意构造和解析 DNS 消息，来满足实验需求。
## xperi 子包

`xperi` 包实现了一些实验用函数，特别是 DNSSEC 相关的辅助函数，包括：

   - `ParseKeyBase64` 用于解析 Base64 编码的 DNSKEY 为字节形式。

   - `CalculateKeyTag` 用于计算 DNSKEY 的 Key Tag。

   - `GenerateRDATADNSKEY` 根据参数生成 DNSKEY RDATA。

   - `GenerateRDATARRSIG` 根据参数对RRSET进行签名，生成 RRSIG RDATA。

   - `GenerateRDATADS` 根据参数生成 DNSKEY 的 DS RDATA。

   - `GenerateRRDNSKEY` 根据参数生成 DNSKEY RR。

   - `GenerateRRRRSIG` 根据参数对RRSET进行签名，生成 RRSIG RR。

   - `GenerateRRDS` 根据参数生成 DNSKEY 的 DS RR。

   - `GenRandomRRSIG` 用于生成一个随机的 RRSIG RDATA。

   - `GenWrongKeyWithTag` 用于生成错误的，但具有指定 KeyTag 的 DNSKEY RDATA。

   - `GenKeyWithTag` **[该函数十分耗时]** 用于生成一个具有指定 KeyTag 的 DNSKEY。

## 许可证

本项目遵循 [GPL-3.0 许可证](LICENSE)。

---

如需更多信息或支持，请访问我们的 [GitHub 页面](https://github.com/TochusC/godns)。