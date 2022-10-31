package bgpsrv

import "errors"

type Neighbor struct {
	Address string
	ASN     uint32
}

type ServerConfig struct {
	routerID         string
	routerASN        uint32
	peerASN          uint32
	peerAuthPassword string
	nextHopIPv4      string
	nextHopIPv6      string
	peerNets         []string
	port             int32
	addrs            []string
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		routerID:  "1.3.3.7",
		routerASN: 65543,
		peerASN:   65542,
		peerNets: []string{
			"0.0.0.0/0",
			"::/0",
		},
		nextHopIPv4: "87.250.250.242",
		nextHopIPv6: "2a02:6b8::2:242",
		port:        179,
	}
}

func (c *ServerConfig) WithRouterASN(asn uint32) *ServerConfig {
	c.routerASN = asn
	return c
}

func (c *ServerConfig) WithRouterID(routeID string) *ServerConfig {
	c.routerID = routeID
	return c
}

func (c *ServerConfig) WithListenPort(port int32) *ServerConfig {
	c.port = port
	return c
}

func (c *ServerConfig) WithListenAddr(addrs ...string) *ServerConfig {
	c.addrs = addrs
	return c
}

func (c *ServerConfig) WithPeerASN(asn uint32) *ServerConfig {
	c.peerASN = asn
	return c
}

func (c *ServerConfig) WithPeerAuthPassword(password string) *ServerConfig {
	c.peerAuthPassword = password
	return c
}

func (c *ServerConfig) WithPeerNet(nets ...string) *ServerConfig {
	c.peerNets = nets
	return c
}

func (c *ServerConfig) WithNextHopIPv4(hop string) *ServerConfig {
	c.nextHopIPv4 = hop
	return c
}

func (c *ServerConfig) WithNextHopIPv6(hop string) *ServerConfig {
	c.nextHopIPv6 = hop
	return c
}

func (c *ServerConfig) Build() *ServerConfig {
	return c
}

func (c *ServerConfig) Validate() error {
	if c.routerASN == 0 {
		return errors.New("ASN can't be empty")
	}

	return nil
}
