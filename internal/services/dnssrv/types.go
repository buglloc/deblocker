package dnssrv

import (
	"net"
)

type RR struct {
	FQDN string
	Kind IPKind
	IP   net.IP
	TTL  uint32
}

type handleFilter func(RR, net.IP) bool
type IPHandler func(RR)
