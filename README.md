# GoDNS

[![madewithlove](https://img.shields.io/badge/made_with-%E2%9D%A4-red?style=for-the-badge&labelColor=orange&style=flat-square)](https://github.com/TochusC/godns)
![Go Version](https://img.shields.io/github/go-mod/go-version/tochusc/godns/master?filename=go.mod&style=flat-square)
![Latest Version](https://img.shields.io/github/v/tag/tochusc/godns?label=latest&style=flat-square)
![License](https://img.shields.io/github/license/tochusc/godns?style=flat-square)
[![GoDoc](https://godoc.org/github.com/tochusc/godns?status.svg)](https://godoc.org/github.com/tochusc/godns)

[简体中文](README.md) | [English](docs/en/README.md)

GoDNS 是一个快速、灵活的**实验用** DNS 服务器，旨在帮助开发者和研究人员探索和实验 DNS 协议的各种特性。

## 目录

- [概述](#概述)
- [GoDNSServer](#godnsserver)
- [示例](#示例)
- [构造和生成 DNS 回复](#构造和生成-dns-回复)
- [dns 包](#dns-包)
- [xlayers 子包](#xlayers-子包)
- [xperi 子包](#xperi-子包)

## 概述

GoDNSServer 由三部分组成：

1. **ServerConfig**: DNS 服务器的配置。
2. **Sniffer**: 数据包嗅探器，用于监听网络设备和端口。
3. **Handler**: 数据包处理器，负责处理 DNS 请求并生成响应。

## GoDNSServer

`GoDNSServer` 是对 DNS 服务器的最顶层封装，提供了灵活的接口和功能。

### Sniffer

`Sniffer` 用于监听指定的网络设备和端口，嗅探 DNS 请求。

### Handler

`Handler` 负责处理 DNS 请求并生成回复，内部包含以下四部分：

- **Parser**: 解析 DNS 请求。
- **Responser**: 生成 DNS 回复。
- **Sender**: 发送 DNS 回复。
- **DNSServerConfig**: 记录 DNS 服务器的配置。

## 示例

通过下述几行代码，可以一键启动一个基础的 GoDNS 服务器：

```go
// 创建一个 DNS 服务器
server := &GoDNSServer{
    ServerConfig: serverConf,
    Sniffer: []*Sniffer{
        NewSniffer(SnifferConfig{
            Device:   serverConf.NetworkDevice,
            Port:     serverConf.Port,
            PktMax:   65535,
            Protocol: ProtocolUDP,
        }),
    },
    Handler: NewHandler(serverConf, &DullResponser{}),
}
server.Start()
```

## 构造和生成 DNS 回复

`Handler` 用于响应、处理 DNS 请求并回复。实现 `Responser` 接口，可以自定义 DNS 回复的生成方式。

`responser.go` 文件中提供了若干的 `Responser` 实现示例，以供参考。

## dns 包

`dns` 包使用 Go 的内置函数提供对 DNS 消息的编解码实现。

### DNSMessage

`DNSMessage` 结构表示 DNS 协议的消息，包括：

- **Header**: DNS 头部。
- **Question**: DNS 查询部分。
- **Answer**: DNS 回答部分。
- **Authority**: 权威部分。
- **Additional**: 附加部分。

dns包支持对未知类型的资源记录进行编解码，灵活满足实验需求。

## xlayers 子包

`xlayers` 包提供了实现 `gopacket.Layer` 接口的 DNS 封装结构，可用于替换 `gopacket.Layer` 中原有的 DNS 实现。

```go
// DNS 结构体可用于替换 gopacket.Layer 中原有的 DNS 实现
type DNS struct {
    layers.BaseLayer
    DNSMessage dns.DNSMessage
}
```

## xperi 子包

`xperi` 包实现了一些实验用函数，特别是 DNSSEC 相关的辅助函数，包括：

- `ParseKeyBase64`: 解析 Base64 编码的 DNSKEY。
- `CalculateKeyTag`: 计算 DNSKEY 的 Key Tag。
- `GenerateDNSKEY`: 生成 DNSKEY RDATA。
- `GenerateRRSIG`: 对 RRSET 进行签名生成 RRSIG RDATA。
- `GenerateDS`: 生成 DNSKEY 的 DS RDATA。
- `GenRandomRRSIG`: 生成随机的 RRSIG RDATA。
- `GenWrongKeyWithTag`: 生成错误的 DNSKEY RDATA，带有指定 KeyTag。
- `GenKeyWithTag`: 生成具有指定 KeyTag 的 DNSKEY（此函数较耗时）。

## 许可证

本项目遵循 [GPL-3.0 许可证](LICENSE)。

---

如需更多信息或支持，请访问我们的 [GitHub 页面](https://github.com/TochusC/godns)。