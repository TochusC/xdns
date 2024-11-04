// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// xperi 包实现了一些实验用函数。
//
// # dnssec.go 文件提供了一系列 DNSSEC 相关实验辅助函数。
//   - ParseKeyBase64 用于解析 Base64 编码的 DNSKEY 为字节形式。
//   - CalculateKeyTag 用于计算 DNSKEY 的 Key Tag。
//   - GenerateDNSKEY 根据参数生成 DNSKEY RDATA。
//   - GenerateRRSIG 根据参数对RRSET进行签名，生成 RRSIG RDATA。
//   - GenerateDS 根据参数生成 DNSKEY 的 DS RDATA。
//   - GenRandomRRSIG 用于生成一个随机的 RRSIG RDATA。
//   - GenWrongKeyWithTag 用于生成错误的，但具有指定 KeyTag 的 DNSKEY RDATA。
//   - GenKeyWithTag [该函数十分耗时] 用于生成一个具有指定 KeyTag 的 DNSKEY。
package xperi
