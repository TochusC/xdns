// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// dnssec.go 提供了一些DNSSEC相关的测试用函数。

package xperi

import (
	"crypto/rand"
	"fmt"

	"github.com/tochusc/godns/dns"
)

// GenWrongKey 生成一个具有指定KeyTag，且能通过检验，但错误的 DNSKEY RDATA
// 传入参数：
//   - algo: DNSSEC 算法
//   - flag: DNSKEY Flag
//   - tag: Key Tag
//
// 返回值：
//   - 你想要的 DNSKEY RDATA
func GenWrongKeyWithTag(algo dns.DNSSECAlgorithm, flag dns.DNSKEYFlag, tag int) dns.DNSRDATADNSKEY {
	algorithmer := dns.DNSSECAlgorithmerFactory(algo)
	_, pubKey := algorithmer.GenerateKey()
	pKey := dns.DNSRDATADNSKEY{
		Flags:     flag,
		Protocol:  3,
		Algorithm: algo,
		PublicKey: pubKey,
	}

	rTag := dns.CalculateKeyTag(pKey)
	dif := tag - int(rTag)

	fmt.Printf("rTag:%d, tTag:%d, dif: %d\n", rTag, tag, dif)

	if dif < 0 {
		dif = -dif
		hDif := dif >> 8
		lDif := dif & 0xFF

		for tvlr, _ := range pubKey {
			if tvlr&1 == 0 {
				if int(pubKey[tvlr])-int(hDif) < 0 {
					pubKey[tvlr] = 0
					hDif -= int(pubKey[tvlr])
				} else {
					pubKey[tvlr] -= byte(hDif)
					hDif = 0
				}
			} else {
				if int(pubKey[tvlr])-int(hDif) < 0 {
					pubKey[tvlr] = 0
					lDif -= int(pubKey[tvlr])
				} else {
					pubKey[tvlr] -= byte(lDif)
					lDif = 0
				}
			}
			if hDif == 0 && lDif == 0 {
				break
			}
		}
	} else {
		hDif := dif >> 8
		lDif := dif & 0xFF

		for tvlr, _ := range pubKey {
			if tvlr&1 == 0 {
				if int(pubKey[tvlr])+int(hDif) > 0xFF {
					pubKey[tvlr] = 0xFF
					hDif -= int(0xFF) - int(pubKey[tvlr])
				} else {
					pubKey[tvlr] += byte(hDif)
					hDif = 0
				}
			} else {
				if int(pubKey[tvlr])+int(lDif) > 0xFF {
					pubKey[tvlr] = 0xFF
					lDif -= int(0xFF) - int(pubKey[tvlr])
				} else {
					pubKey[tvlr] += byte(lDif)
					lDif = 0
				}
			}
			if hDif == 0 && lDif == 0 {
				break
			}
		}
	}

	// 重新计算 Key Tag, 算法不能保证成功
	if rTag != uint16(tag) {
		return GenWrongKeyWithTag(algo, flag, tag)
	}

	return pKey
}

// GenKeyWithTag 生成一个具有指定KeyTag的 DNSKEY RDATA
// 传入参数：
//   - algo: DNSSEC 算法
//   - flag: DNSKEY Flag
//   - tag: Key Tag
//
// 返回值：
//   - 你想要的 DNSKEY RDATA
//
// 注意：这个函数会十分耗时，因为它会尝试生成大量的密钥对，直到找到一个符合要求的密钥对。
func GenKeyWithTag(algo dns.DNSSECAlgorithm, flag dns.DNSKEYFlag, tag int) dns.DNSRDATADNSKEY {
	for {
		algorithmer := dns.DNSSECAlgorithmerFactory(algo)
		_, pubKey := algorithmer.GenerateKey()
		pKey := dns.DNSRDATADNSKEY{
			Flags:     flag,
			Protocol:  3,
			Algorithm: algo,
			PublicKey: pubKey,
		}

		rTag := dns.CalculateKeyTag(pKey)
		if int(rTag) == tag {
			return pKey
		}
	}
}

// GenRandomRRSIG 生成一个随机(同时也会是错误的)的 RRSIG RDATA
// 传入参数：
//   - rrSet: 要签名的 RR 集合
//   - algo: 签名算法
//   - expiration: 签名过期时间
//   - inception: 签名生效时间
//   - keyTag: 签名公钥的 Key Tag
//   - signerName: 签名者名称
//
// 返回值：
//   - 你想要的 RRSIG RDATA
func GenRandomRRSIG(rrSet []dns.DNSResourceRecord, algo dns.DNSSECAlgorithm,
	expiration, inception uint32, keyTag uint16, signerName string) dns.DNSRDATARRSIG {

	algorithmer := dns.DNSSECAlgorithmerFactory(algo)
	privKey, _ := algorithmer.GenerateKey()
	rText := []byte("random plaintext")
	sig, err := algorithmer.Sign(rText, privKey)
	if err != nil {
		panic(fmt.Sprintf("function GenRandomRRSIG() failed:\n%s", err))
	}

	_, err = rand.Read(sig)
	if err != nil {
		panic(fmt.Sprintf("function GenRandomRRSIG() failed:\n%s", err))
	}

	return dns.DNSRDATARRSIG{
		TypeCovered: rrSet[0].Type,
		Algorithm:   algo,
		Labels:      uint8(dns.CountDomainNameLabels(&rrSet[0].Name)),
		OriginalTTL: 3600,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  signerName,
		Signature:   sig,
	}
}
