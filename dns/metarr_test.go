package dns

import "testing"

func TestPersudoRRString(t *testing.T) {
	rdata := DNSRDATAOPT{
		OptionCode:   0,
		OptionLength: 4,
		OptionData:   []byte{0x00, 0x01, 0x02, 0x03},
	}

	rr := NewDNSRROPT(1024,
		int(SetDNSRROPTTTL(0, 41, true, 0)),
		&rdata,
	)

	prr := NewPersudoRR(rr)
	t.Logf("PersudoRR String():\n%s", prr.String())
}
