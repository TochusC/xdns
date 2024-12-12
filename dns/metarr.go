package dns

import (
	"encoding/binary"
	"fmt"
)

var PersudoRRType = map[DNSType]interface{}{
	DNSRRTypeOPT: nil,
}

func IsPersudoRR(rr *DNSResourceRecord) bool {
	_, ok := PersudoRRType[rr.Type]
	return ok
}

// DNSRROPT is a DNS Resource Record OPT
// See RFC 6891

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

type PersudoRR interface {
	String() string
}

func NewPersudoRR(rr *DNSResourceRecord) PersudoRR {
	switch rr.Type {
	case DNSRRTypeOPT:
		return &DNSRROPT{rr}
	default:
		return nil
	}
}

type DNSRROPT struct {
	rr *DNSResourceRecord
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
		"### Persudo Rersouce Record OPT ###\n",
		"UDP Payload Size:", int(rr.Class), "\n",
		"Extended RCODE:", ercode, "\n",
		"Version:", version, "\n",
		"DO:", do, "\n",
		"Z: ", z, "\n",
		"RData:\n", rr.RData.String(),
	)
}
