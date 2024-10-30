// Copyright 2024 TochusC, AOSP Lab. All rights reserved.

// dnssec.go 文件定义了 DNSSEC 所使用到的一些工具函数

package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
)

func CalculateKeyTag(key DNSRDATADNSKEY) uint16 {
	rdata := key.Encode()
	var ac uint32
	for i := 0; i < len(rdata); i++ {
		if i&1 == 1 {
			ac += uint32(rdata[i])
		} else {
			ac += uint32(rdata[i]) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// GenerateRRSIG 生成 RRSIG RDATA
// signature = sign(RRSIG_RDATA | RR(1) | RR(2) | ...)
func GenerateRRSIG(rrSet []DNSResourceRecord, algo DNSSECAlgorithm,
	expiration, inception uint32, keyTag uint16,
	signerName string, privKey []byte) DNSRDATARRSIG {

	// signature = sign(RRSIG_RDATA | RR(1) | RR(2) | ...)
	// RRSIG_RDATA
	rrsig := DNSRDATARRSIG{
		TypeCovered: rrSet[0].Type,
		Algorithm:   algo,
		Labels:      uint8(CountDomainNameLabels(&rrSet[0].Name)),
		OriginalTTL: rrSet[0].TTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      uint16(keyTag),
		SignerName:  signerName,
		Signature:   []byte{},
	}

	plainLen := rrsig.Size()
	for _, rr := range rrSet {
		plainLen += rr.Size()
	}
	plainText := make([]byte, plainLen)
	offset, err := rrsig.EncodeToBuffer(plainText)
	if err != nil {
		panic(fmt.Sprintf("failed to encode RRSIG RDATA: %s", err))
	}
	// TODO: Canonicalize the RRs

	// RR = owner | type | class | TTL | RDATA length | RDATA
	for _, rr := range rrSet {
		increment, err := rr.EncodeToBuffer(plainText[offset:])
		if err != nil {
			panic(fmt.Sprintf("failed to encode RR: %s", err))
		}
		offset += increment
	}

	if offset != plainLen {
		panic("failed to encode RRSIG RDATA: unexpected offset")
	}

	var signature []byte
	switch algo {
	case DNSSECAlgorithmRSASHA1:
		signature, err = RSASHA1Sign(plainText, privKey)
	case DNSSECAlgorithmRSASHA256:
		signature, err = RSASHA256Sign(plainText, privKey)
	case DNSSECAlgorithmRSASHA512:
		signature, err = RSASHA512Sign(plainText, privKey)
	case DNSSECAlgorithmECDSAP256SHA256:
		signature, err = ECDSAP256SHA256Sign(plainText, privKey)
	case DNSSECAlgorithmECDSAP384SHA384:
		signature, err = ECDSAP384SHA384Sign(plainText, privKey)
	default:
		panic(fmt.Sprintf("unsupported algorithm: %d", algo))
	}
	if err != nil {
		panic(fmt.Sprintf("failed to sign RRSIG: %s", err))
	}

	rrsig.Signature = signature

	return rrsig
}

// ECDSAP256SHA256Sign 使用 ECDSA-P256-SHA256 算法对数据进行签名
func ECDSAP256SHA256Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha256.Sum256(data)

	// 重建 ECDSA 私钥
	curve := elliptic.P256()
	pKey := new(ecdsa.PrivateKey)
	pKey.PublicKey.Curve = curve
	pKey.D = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.X, pKey.PublicKey.Y = curve.ScalarBaseMult(privKey)

	// 签名
	r, s, err := ecdsa.Sign(nil, pKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}

// RSASHA1Sign 使用 RSA-SHA1 算法对数据进行签名
func RSASHA1Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha1.Sum(data)

	// 重建 RSA 私钥
	pKey := new(rsa.PrivateKey)
	pKey.D = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.N = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.E = 3

	// 签名
	signature, err := rsa.SignPKCS1v15(nil, pKey, crypto.SHA1, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return signature, nil
}

// RSASHA256Sign 使用 RSA-SHA256 算法对数据进行签名
func RSASHA256Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha256.Sum256(data)

	// 重建 RSA 私钥
	pKey := new(rsa.PrivateKey)
	pKey.D = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.N = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.E = 3

	// 签名
	signature, err := rsa.SignPKCS1v15(nil, pKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return signature, nil
}

func RSASHA512Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha512.Sum512(data)

	// 重建 RSA 私钥
	pKey := new(rsa.PrivateKey)
	pKey.D = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.N = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.E = 3

	// 签名
	signature, err := rsa.SignPKCS1v15(nil, pKey, crypto.SHA512, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return signature, nil
}

// ECDSAP384SHA384Sign 使用 ECDSA-P384-SHA384 算法对数据进行签名
func ECDSAP384SHA384Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha512.Sum384(data)

	// 重建 ECDSA 私钥
	curve := elliptic.P384()
	pKey := new(ecdsa.PrivateKey)
	pKey.PublicKey.Curve = curve
	pKey.D = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.X, pKey.PublicKey.Y = curve.ScalarBaseMult(privKey)

	// 签名
	r, s, err := ecdsa.Sign(nil, pKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}
