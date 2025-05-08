// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// dnssec.go 提供了一些DNSSEC相关的实验用函数，可能会发现它们非常有用。

package xperi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	mrand "math/rand"

	"github.com/tochusc/xdns/dns"
)

// ParseKeyBase64 解析 Base64 编码的密钥为字节切片
func ParseKeyBase64(keyb64 string) []byte {
	keyBytes, err := base64.StdEncoding.DecodeString(keyb64)
	if err != nil {
		panic(fmt.Sprintf("failed to decode base64 key: %s", err))
	}
	return keyBytes
}

// CalculateKeyTag 计算 DNSKEY 的 Key Tag
//   - 传入 DNSKEY RDATA
//   - 返回 Key Tag
//
// Key Tag 是 DNSKEY 的一个 16 位无符号整数，用于快速识别 DNSKEY
func CalculateKeyTag(key dns.DNSRDATADNSKEY) uint16 {
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

// GenerateRDATADNSKEY 生成公钥的 DNSKEY RDATA, 并返回私钥字节
// 传入参数：
//   - algo: DNSSEC 算法
//   - flag: DNSKEY Flag
//
// 返回值：
//   - 公钥 DNSKEY RDATA
//   - 私钥字节
func GenerateRDATADNSKEY(algo dns.DNSSECAlgorithm, flag dns.DNSKEYFlag) (dns.DNSRDATADNSKEY, []byte) {
	algorithmer := DNSSECAlgorithmerFactory(algo)
	privKey, pubKey := algorithmer.GenerateKey()
	return dns.DNSRDATADNSKEY{
		Flags:     flag,
		Protocol:  3,
		Algorithm: algo,
		PublicKey: pubKey,
	}, privKey
}

// GenerateRRDNSKEY 生成 DNSKEY RR，并返回私钥字节
// 传入参数：
//   - algo: DNSSEC 算法
//   - flag: DNSKEY Flag
//
// 返回值：
//   - DNSKEY RR
//   - 私钥字节
func GenerateRRDNSKEY(
	zName string, algo dns.DNSSECAlgorithm, flag dns.DNSKEYFlag) (dns.DNSResourceRecord, []byte) {
	rdata, privKey := GenerateRDATADNSKEY(algo, flag)
	rr := dns.DNSResourceRecord{
		Name:  *dns.NewDNSName(zName),
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(rdata.Size()),
		RData: &rdata,
	}
	return rr, privKey
}

// GenerateRDATARRSIG 根据传入参数生成 RRSIG RDATA，
// 该函数目前无法将传入的 RRSET 进行 规范化 及 规范化排序，
// 所以需要外部保证传入的 RRSET 是规范的，才可以成功生成正确的 RRSIG。
// 传入参数：
//   - rrSet: 要签名的 RR 集合
//   - algo: 签名算法
//   - expiration: 签名过期时间
//   - inception: 签名生效时间
//   - keyTag: 签名公钥的 Key Tag
//   - signerName: 签名者名称
//   - privKey: 签名私钥的 字节编码
//
// 返回值：
//   - RRSIG RDATA
//
// signature = sign(RRSIG_RDATA | RR(1) | RR(2) | ...)
func GenerateRDATARRSIG(rrSet []dns.DNSResourceRecord, algo dns.DNSSECAlgorithm,
	expiration, inception uint32, keyTag uint16,
	signerName string, privKey []byte) dns.DNSRDATARRSIG {

	// signature = sign(RRSIG_RDATA | RR(1) | RR(2) | ...)
	// RRSIG_RDATA
	rrsig := dns.DNSRDATARRSIG{
		TypeCovered: rrSet[0].Type,
		Algorithm:   algo,
		Labels:      uint8(dns.CountDomainNameLabels(&rrSet[0].Name.DomainName)),
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
	// TODO: 规范化RRSET，Canonicalize the RRs
	// 现在只能依赖于外部保证传入的 RRSET 是规范的
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

	// 接口以及工厂模式 Coooool
	var signature []byte
	algorithmer := DNSSECAlgorithmerFactory(algo)
	signature, err = algorithmer.Sign(plainText, privKey)
	if err != nil {
		panic(fmt.Sprintf("failed to sign RRSIG: %s", err))
	}

	rrsig.Signature = signature

	return rrsig
}

// GenerateRRRRSIG 根据传入参数生成 RRSIG RR
// 传入参数：
//   - rrSet: 要签名的 RR 集合
//   - algo: 签名算法
//   - expiration: 签名过期时间
//   - inception: 签名生效时间
//   - keyTag: 签名公钥的 Key Tag
//   - signerName: 签名者名称
//   - privKey: 签名私钥的 字节编码
//
// 返回值：
//   - RRSIG RR
func GenerateRRRRSIG(rrSet []dns.DNSResourceRecord, algo dns.DNSSECAlgorithm,
	expiration, inception uint32, keyTag uint16,
	signerName string, privKey []byte) dns.DNSResourceRecord {
	rdata := GenerateRDATARRSIG(rrSet, algo, expiration, inception, keyTag, signerName, privKey)
	rr := dns.DNSResourceRecord{
		Name:  rrSet[0].Name,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(rdata.Size()),
		RData: &rdata,
	}
	return rr
}

// GenerateRDATADS 生成 DNSKEY 的 DS RDATA
// 传入参数：
//   - oName: DNSKEY 的所有者名称
//   - kRDATA: DNSKEY RDATA
//   - dType: 所使用的摘要算法类型
//
// 返回值：
//   - DS RDATA
//
// digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
func GenerateRDATADS(oName string, kRDATA dns.DNSRDATADNSKEY, dType dns.DNSSECDigestType) dns.DNSRDATADS {
	// 1. 计算 DNSKEY 的 Key Tag
	keyTag := CalculateKeyTag(kRDATA)

	// 2. 构建明文
	pText := make([]byte, dns.GetDomainNameWireLen(&oName)+kRDATA.Size())
	offset, err := dns.NewDNSName(oName).EncodeToBuffer(pText)
	if err != nil {
		panic(fmt.Sprintf("failed to write domain name: %s", err))
	}
	_, err = kRDATA.EncodeToBuffer(pText[offset:])
	if err != nil {
		panic(fmt.Sprintf("failed to encode DNSKEY RDATA: %s", err))
	}

	var digest []byte
	// 3. 计算摘要
	switch dType {
	case dns.DNSSECDigestTypeSHA1:
		nDigest := sha1.Sum(pText)
		digest = nDigest[:]
	case dns.DNSSECDigestTypeSHA256:
		nDigest := sha256.Sum256(pText)
		digest = nDigest[:]
	case dns.DNSSECDigestTypeSHA384:
		nDigest := sha512.Sum384(pText)
		digest = nDigest[:]

	default:
		panic(fmt.Sprintf("unsupported digest type: %d", dType))
	}

	// 4. 构建 DS RDATA
	return dns.DNSRDATADS{
		KeyTag:     keyTag,
		Algorithm:  kRDATA.Algorithm,
		DigestType: dType,
		Digest:     digest[:],
	}
}

// GenerateRRDS 生成 DNSKEY 的 DS RR
// 传入参数：
//   - oName: DNSKEY 的所有者名称
//   - kRDATA: DNSKEY RDATA
//   - dType: 所使用的摘要算法类型
//
// 返回值：
//   - DS RR
func GenerateRRDS(oName string, kRDATA dns.DNSRDATADNSKEY, dType dns.DNSSECDigestType) dns.DNSResourceRecord {
	rdata := GenerateRDATADS(oName, kRDATA, dType)
	rr := dns.DNSResourceRecord{
		Name:  *dns.NewDNSName(oName),
		Type:  dns.DNSRRTypeDS,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(rdata.Size()),
		RData: &rdata,
	}
	return rr
}

// GenerateRandomDNSKEYWithTag 生成一个具有指定KeyTag，且能通过检验，但错误的 DNSKEY RDATA
// 传入参数：
//   - algo: DNSSEC 算法
//   - flag: DNSKEY Flag
//   - tag: Key Tag
//
// 返回值：
//   - 你想要的 DNSKEY RDATA
func GenerateCollidedDNSKEY(rdata dns.DNSRDATADNSKEY) dns.DNSRDATADNSKEY {

	keyLen := len(rdata.PublicKey)

	keyByte := make([]byte, keyLen)
	copy(keyByte, rdata.PublicKey)

	randomIndexPlus := mrand.Intn(keyLen/2) + 1
	randomIndexMinus := mrand.Intn(keyLen/2) + 1

	for randomIndexPlus == randomIndexMinus {
		randomIndexMinus = mrand.Intn(keyLen/2) + 1
	}

	randomOffset := uint8(mrand.Intn(128)) + 1

	keyByte[randomIndexPlus*2-1] = keyByte[randomIndexPlus*2-1] + randomOffset
	if keyByte[randomIndexPlus*2-1] < randomOffset {
		keyByte[randomIndexPlus*2-2] = keyByte[randomIndexPlus*2-2] + 1
	}

	keyByte[randomIndexMinus*2-1] = keyByte[randomIndexMinus*2-1] - randomOffset
	if keyByte[randomIndexMinus*2-1] > 255-randomOffset {
		keyByte[randomIndexMinus*2-2] = keyByte[randomIndexMinus*2-2] - 1
	}

	pKey := dns.DNSRDATADNSKEY{
		Flags:     rdata.Flags,
		Protocol:  rdata.Protocol,
		Algorithm: rdata.Algorithm,
		PublicKey: keyByte,
	}

	return pKey
}

// GenerateDNSKEYWithTag 生成一个具有指定KeyTag的 DNSKEY RDATA
// 传入参数：
//   - algo: DNSSEC 算法
//   - flag: DNSKEY Flag
//   - tag: Key Tag
//
// 返回值：
//   - 你想要的 DNSKEY RDATA
func GenerateDNSKEYWithTag(rdata dns.DNSRDATADNSKEY, i int) dns.DNSRDATADNSKEY {
	kbLen := len(rdata.PublicKey)
	kb := make([]byte, kbLen)
	copy(kb, rdata.PublicKey)
	randomIndex := mrand.Intn(kbLen/2) + 1

	lowOff := uint8(i % 256)
	highOff := uint8(i / 256)

	for kb[randomIndex*2-2] < highOff {
		randomIndex = mrand.Intn(kbLen/2) + 1
	}
	kb[randomIndex*2-2] = kb[randomIndex*2-2] - highOff

	kb[randomIndex*2-1] = kb[randomIndex*2-1] - lowOff
	if kb[randomIndex*2-1] > 255-lowOff {
		kb[randomIndex*2-2] = kb[randomIndex*2-2] - 1
	}

	return dns.DNSRDATADNSKEY{
		Flags:     rdata.Flags,
		Protocol:  rdata.Protocol,
		Algorithm: rdata.Algorithm,
		PublicKey: kb,
	}
}

// RandomCharSet 随机字符集
var RandomCharSet = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// GenerateRandomString 生成一个随机字符串
func GenerateRandomString(length int) string {
	str := make([]byte, length)
	_, err := rand.Read(str)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random string: %s", err))
	}
	for i := 0; i < length; i++ {
		str[i] = RandomCharSet[int(str[i])%62]
	}
	return string(str)
}

// GenerateRandomRDATARRSIG 生成一个随机(同时也会是错误的)的 RRSIG RDATA
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
func GenerateRandomRDATARRSIG(rrSet []dns.DNSResourceRecord, algo dns.DNSSECAlgorithm,
	expiration, inception uint32, keyTag uint16, signerName string) dns.DNSRDATARRSIG {

	var sigLen int
	switch algo {
	case dns.DNSSECAlgorithmRSASHA1:
		sigLen = 128
	case dns.DNSSECAlgorithmRSASHA256:
		sigLen = 256
	case dns.DNSSECAlgorithmRSASHA512:
		sigLen = 512
	case dns.DNSSECAlgorithmECDSAP256SHA256:
		sigLen = 64
	case dns.DNSSECAlgorithmECDSAP384SHA384:
		sigLen = 96
	case dns.DNSSECAlgorithmED25519:
		sigLen = 64
	default:
		panic(fmt.Sprintf("unsupported algorithm: %d", algo))
	}

	sig := make([]byte, sigLen)
	_, err := rand.Read(sig)
	if err != nil {
		panic(fmt.Sprintf("function GenerateRandomRRSIG() failed:\n%s", err))
	}

	return dns.DNSRDATARRSIG{
		TypeCovered: rrSet[0].Type,
		Algorithm:   algo,
		Labels:      uint8(dns.CountDomainNameLabels(&rrSet[0].Name.DomainName)),
		OriginalTTL: 8,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  signerName,
		Signature:   sig,
	}
}

// GenerateRandomRRSIG 生成一个随机(同时也会是错误的)的 RRSIG RR
// 传入参数：
//   - rrSet: 要签名的 RR 集合
//   - algo: 签名算法
//   - expiration: 签名过期时间
//   - inception: 签名生效时间
//   - keyTag: 签名公钥的 Key Tag
//   - signerName: 签名者名称
func GenerateRandomRRRRSIG(rrSet []dns.DNSResourceRecord, algo dns.DNSSECAlgorithm,
	expiration, inception uint32, keyTag uint16, signerName string) dns.DNSResourceRecord {
	rdata := GenerateRandomRDATARRSIG(rrSet, algo, expiration, inception, keyTag, signerName)
	rr := dns.DNSResourceRecord{
		Name:  rrSet[0].Name,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(rdata.Size()),
		RData: &rdata,
	}
	return rr
}

func GenerateRandomRDATADS(oName string, keytag int, algo dns.DNSSECAlgorithm, dType dns.DNSSECDigestType) dns.DNSRDATADS {

	var digestLen int
	switch dType {
	case dns.DNSSECDigestTypeSHA1:
		digestLen = 20
	case dns.DNSSECDigestTypeSHA256:
		digestLen = 32
	case dns.DNSSECDigestTypeSHA384:
		digestLen = 48
	default:
		panic(fmt.Sprintf("unsupported digest type: %d", dType))
	}

	digest := make([]byte, digestLen)
	_, err := rand.Read(digest)
	if err != nil {
		panic(fmt.Sprintf("function GenerateRandomDS() failed:\n%s", err))
	}

	// 4. 构建 DS RDATA
	return dns.DNSRDATADS{
		KeyTag:     uint16(keytag),
		Algorithm:  algo,
		DigestType: dType,
		Digest:     digest[:],
	}
}

func GenerateRandomRRDS(oName string, keytag int, algo dns.DNSSECAlgorithm, dType dns.DNSSECDigestType) dns.DNSResourceRecord {
	rdata := GenerateRandomRDATADS(oName, keytag, algo, dType)
	rr := dns.DNSResourceRecord{
		Name:  *dns.NewDNSName(oName),
		Type:  dns.DNSRRTypeDS,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(rdata.Size()),
		RData: &rdata,
	}
	return rr
}

// DNSSECAlgorithmer DNSSEC 算法接口
type DNSSECAlgorithmer interface {
	// Sign 使用私钥对数据进行签名
	Sign(data, privKey []byte) ([]byte, error)
	// GenerateKey 生成密钥对
	GenerateKey() ([]byte, []byte)
}

// DNSSECAlgorithmFactory 生成 DNSSECAlgorithmer
// ECDSAP系列算法有概率生成失败...具体原因仍不清楚
func DNSSECAlgorithmerFactory(algo dns.DNSSECAlgorithm) DNSSECAlgorithmer {
	switch algo {
	case dns.DNSSECAlgorithmRSASHA1:
		return RSASHA1{}
	case dns.DNSSECAlgorithmRSASHA256:
		return RSASHA256{}
	case dns.DNSSECAlgorithmRSASHA512:
		return RSASHA512{}
	case dns.DNSSECAlgorithmECDSAP256SHA256:
		return ECDSAP256SHA256{}
	case dns.DNSSECAlgorithmECDSAP384SHA384:
		return ECDSAP384SHA384{}
	case dns.DNSSECAlgorithmED25519:
		return ED25519{}
	default:
		panic(fmt.Sprintf("unsupported algorithm: %d", algo))
	}
}

type RSASHA1 struct{}

func (RSASHA1) Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha1.Sum(data)

	// 重建 RSA 私钥
	pKey, err := x509.ParsePKCS1PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %s", err)
	}

	// 签名
	signature, err := rsa.SignPKCS1v15(nil, pKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return signature, nil
}

func (RSASHA1) GenerateKey() ([]byte, []byte) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key: %s", err))
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal public key: %s", err))
	}

	return privKeyBytes, pubKeyBytes
}

type RSASHA256 struct{}

func (RSASHA256) Sign(data, privKey []byte) ([]byte, error) {
	copied_data := make([]byte, len(data))
	copy(copied_data, data)
	copied_key := make([]byte, len(privKey))
	copy(copied_key, privKey)

	// 计算明文摘要
	digest := sha256.Sum256(copied_data)

	// 重建 RSA 私钥
	pKey, err := x509.ParsePKCS1PrivateKey(copied_key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %s", err)
	}

	// 签名
	signature, err := rsa.SignPKCS1v15(nil, pKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return signature, nil
}

func (RSASHA256) GenerateKey() ([]byte, []byte) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key: %s", err))
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal public key: %s", err))
	}

	return privKeyBytes, pubKeyBytes
}

type RSASHA512 struct{}

func (RSASHA512) Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha512.Sum512(data)

	// 重建 RSA 私钥
	pKey, err := x509.ParsePKCS1PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %s", err)
	}

	// 签名
	signature, err := rsa.SignPKCS1v15(nil, pKey, crypto.SHA512, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	return signature, nil
}

func (RSASHA512) GenerateKey() ([]byte, []byte) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key: %s", err))
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal public key: %s", err))
	}

	return privKeyBytes, pubKeyBytes
}

type ECDSAP256SHA256 struct{}

func (ECDSAP256SHA256) Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha256.Sum256(data)

	// 重建 ECDSA 私钥
	curve := elliptic.P256()
	pKey := new(ecdsa.PrivateKey)
	pKey.PublicKey.Curve = curve
	pKey.D = new(big.Int).SetBytes(privKey)
	pKey.PublicKey.X, pKey.PublicKey.Y = curve.ScalarBaseMult(privKey)

	// 签名
	r, s, err := ecdsa.Sign(rand.Reader, pKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}

func (ECDSAP256SHA256) GenerateKey() ([]byte, []byte) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate ECDSA key: %s", err))
	}
	privKeyBytes := privKey.D.Bytes()
	pubKeyBytes := append(privKey.PublicKey.X.Bytes(), privKey.PublicKey.Y.Bytes()...)
	return privKeyBytes, pubKeyBytes
}

type ECDSAP384SHA384 struct{}

type MyReader struct {
}

func (MyReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = 1
	}
	return len(p), nil
}

func (ECDSAP384SHA384) Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha512.Sum384(data)

	// 重建 ECDSA 私钥
	var pKey *ecdsa.PrivateKey

	xpkey, err := x509.ParsePKCS8PrivateKey(privKey)
	if err != nil {
		curve := elliptic.P384()
		pKey = new(ecdsa.PrivateKey)
		pKey.PublicKey.Curve = curve
		pKey.D = new(big.Int).SetBytes(privKey)
		pKey.PublicKey.X, pKey.PublicKey.Y = curve.ScalarBaseMult(privKey)
	} else {
		pKey = xpkey.(*ecdsa.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %s", err)
		}
	}

	// 签名
	r, s, err := ecdsa.Sign(MyReader{}, pKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %s", err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	return signature, nil
}

func (ECDSAP384SHA384) GenerateKey() ([]byte, []byte) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate ECDSA key: %s", err))
	}
	privKeyBytes := privKey.D.Bytes()
	pubKeyBytes := append(privKey.PublicKey.X.Bytes(), privKey.PublicKey.Y.Bytes()...)
	return privKeyBytes, pubKeyBytes
}

// ED25519 是 Ed25519 签名算法的实现
type ED25519 struct{}

func (ED25519) Sign(data, privKey []byte) ([]byte, error) {
	// 计算明文摘要
	digest := sha512.Sum512(data)

	// 使用 Ed25519 签名
	signature := ed25519.Sign(privKey, digest[:])

	return signature, nil
}

func (ED25519) GenerateKey() ([]byte, []byte) {
	// 生成 Ed25519 密钥对
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate Ed25519 key: %s", err))
	}
	return privKey, pubKey
}
