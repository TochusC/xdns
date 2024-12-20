package dns

import (
	"encoding/binary"
	"fmt"
)

var PseudoRRType = map[DNSType]interface{}{
	DNSRRTypeOPT: nil,
}

func IsPseudoRR(rr *DNSResourceRecord) bool {
	_, ok := PseudoRRType[rr.Type]
	return ok
}

// NewDNSRROPT creates a new DNS Resource Record OPT
func NewDNSRROPT(udpsize int, ttl int, rdata *DNSRDATAOPT) *DNSResourceRecord {
	return &DNSResourceRecord{
		Name:  ".",
		Type:  41,
		Class: DNSClass(udpsize),
		TTL:   uint32(ttl),
		RDLen: uint16(rdata.Size()),
		RData: rdata,
	}
}

type PseudoRR interface {
	String() string
}

func NewPseudoRR(rr *DNSResourceRecord) PseudoRR {
	switch rr.Type {
	case DNSRRTypeOPT:
		return &DNSRROPT{rr}
	default:
		return nil
	}
}

// DNSRROPT is a DNS Resource Record OPT
// See RFC 6891
//  +------------+--------------+------------------------------+
//  | Field Name | Field Type   | Description                  |
//  +------------+--------------+------------------------------+
//  | NAME       | domain name  | MUST be 0 (root domain)      |
//  | TYPE       | u_int16_t    | OPT (41)                     |
//  | CLASS      | u_int16_t    | requestor’s UDP payload size |
//  | TTL        | u_int32_t    | extended RCODE and flags     |
//  | RDLEN      | u_int16_t    | length of all RDATA          |
//  | RDATA      | octet stream | {attribute,value} pairs      |
//  +------------+--------------+------------------------------+
type DNSRROPT struct {
	rr *DNSResourceRecord
}

// SetDNSRROPTTTL sets the TTL of the OPT RR
// The TTL is encoded as follows:
// (MSB)                            +1 (LSB)
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |         EXTENDED-RCODE        |            VERSION            |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// | DO|                           Z                               |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
func SetDNSRROPTTTL(ercode int, version int, do bool, z int) uint32 {
	var ttl [4]byte
	ttl[0] = uint8(ercode)
	ttl[1] = uint8(version)
	binary.BigEndian.PutUint16(ttl[2:], uint16(z))
	if do {
		ttl[2] |= 0x80
	}
	return binary.BigEndian.Uint32(ttl[:])
}

func (opt *DNSRROPT) String() string {
	rr := opt.rr
	ttl := rr.TTL
	bTTL := make([]byte, 4)
	binary.BigEndian.PutUint32(bTTL, ttl)
	ercode := int(ttl >> 24)
	version := int(ttl >> 16 & 0xff)
	do := (ttl>>15)&1 == 1
	z := int(ttl & 0x7fff)

	return fmt.Sprint(
		"### Pseudo Rersouce Record OPT ###\n",
		"UDP Payload Size:", int(rr.Class), "\n",
		"Extended RCODE:", ercode, "\n",
		"Version:", version, "\n",
		"DO:", do, "\n",
		"Z: ", z, "\n",
		"RData:\n", rr.RData.String(),
	)
}
