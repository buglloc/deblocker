package dnssrv

import (
	"fmt"
	"net"
)

type RR struct {
	FQDN string
	Kind IPKind
	IP   net.IP
	TTL  uint32
}

type ClientFilter func(net.IP) bool
type IPHandler func(RR)
type IPKind uint8

const (
	IPKindNone IPKind = iota
	IPKindV4
	IPKindV6
)

func (k IPKind) String() string {
	switch k {
	case IPKindNone:
		return "none"
	case IPKindV4:
		return "v4"
	case IPKindV6:
		return "v6"
	default:
		return fmt.Sprintf("unknown_%d", uint8(k))
	}
}
