// Copyright 2024 TochusC AOSP Lab. All rights reserved.

// cname.go 文件实现了 CNAME 类型的 DNS 资源记录的 RDATA 编码。
package rdata

import (
	"fmt"

	"github.com/tochusc/godns/dns"
)

// CNAME RDATA 编码格式
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CNAME                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSCNAMERDATA 结构体表示 CNAME 类型的 DNS 资源记录的 RDATA 部分。
// - 其包含一个域名。
// RFC 1035 3.3.1 节 定义了 CNAME 类型的 DNS 资源记录。
// 其 Type 值为 5。
type DNSCNAMERDATA struct {
	CNAME string
}

func (rdata *DNSCNAMERDATA) Type() dns.DNSType {
	return dns.DNSRRTypeCNAME
}

func (rdata *DNSCNAMERDATA) Size() int {
	return len(rdata.CNAME) + 1
}

func (rdata *DNSCNAMERDATA) String() string {
	return fmt.Sprint(
		"### RDATA Section ###\n",
		"CNAME: ", rdata.CNAME, "\n",
		"### End of RDATA Section ###",
	)
}

func (rdata *DNSCNAMERDATA) Encode() []byte {
	return []byte(rdata.CNAME)
}

func (rdata *DNSCNAMERDATA) EncodeToBuffer(buffer []byte) (int, error) {
	if len(buffer) < rdata.Size() {
		return -1, fmt.Errorf("buffer length %d is less than CNAME RDATA size %d", len(buffer), rdata.Size())
	}
	copy(buffer, rdata.Encode())
	return rdata.Size(), nil
}
