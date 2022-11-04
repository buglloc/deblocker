package dnssrv

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/hashicorp/go-multierror"
)

const (
	DefaultMaxTCPQueries = -1
	DefaultTimeout       = 2 * time.Second
)

type ServerConfig struct {
	addrs         []*url.URL
	handleFilters []handleFilter
	handler       IPHandler
	maxTCPQueries int
	readTimeout   time.Duration
	writeTimeout  time.Duration
	err           error
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		addrs: []*url.URL{
			{
				Scheme: "udp",
				Host:   ":53",
			},
		},
		maxTCPQueries: DefaultMaxTCPQueries,
		readTimeout:   DefaultTimeout,
		writeTimeout:  DefaultTimeout,
	}
}

func (c *ServerConfig) WithAddrs(addrs ...string) *ServerConfig {
	c.addrs = make([]*url.URL, len(addrs))
	for i, addr := range addrs {
		u, err := url.Parse(addr)
		if err != nil {
			c.err = multierror.Append(c.err, fmt.Errorf("invalid addr %q: %w", addr, err))
			continue
		}

		c.addrs[i] = u
	}

	return c
}

func (c *ServerConfig) WithObservableNets(nets ...string) *ServerConfig {
	if len(nets) == 0 {
		return c
	}

	allowedNets := make([]*net.IPNet, len(nets))
	for i, cidr := range nets {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			c.err = multierror.Append(c.err, fmt.Errorf("invalid observable net %q: %w", cidr, err))
		}
		allowedNets[i] = ipnet
	}

	c.handleFilters = append(c.handleFilters, func(_ RR, ip net.IP) bool {
		for _, ipnet := range allowedNets {
			if ipnet.Contains(ip) {
				return true
			}
		}

		return false
	})
	return c
}

func (c *ServerConfig) WithObservableIPKinds(kinds ...IPKind) *ServerConfig {
	if len(kinds) == 0 {
		return c
	}

	allowedKinds := make(map[IPKind]struct{}, len(kinds))
	for _, k := range kinds {
		allowedKinds[k] = struct{}{}
	}

	c.handleFilters = append(c.handleFilters, func(rr RR, _ net.IP) bool {
		_, ok := allowedKinds[rr.Kind]
		return ok
	})
	return c
}

func (c *ServerConfig) WithHandler(handler IPHandler) *ServerConfig {
	c.handler = handler
	return c
}

func (c *ServerConfig) WithMaxTCPQueries(maxQueries int) *ServerConfig {
	c.maxTCPQueries = maxQueries
	return c
}

func (c *ServerConfig) WithReadTimeout(timeout time.Duration) *ServerConfig {
	c.readTimeout = timeout
	return c
}

func (c *ServerConfig) WithWriteTimeout(timeout time.Duration) *ServerConfig {
	c.readTimeout = timeout
	return c
}

func (c *ServerConfig) Build() *ServerConfig {
	return c
}

func (c *ServerConfig) Validate() error {
	return c.err
}

type ClientConfig struct {
	net          string
	addr         string
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	err          error
}

func NewClientConfig() *ClientConfig {
	return &ClientConfig{
		dialTimeout:  DefaultTimeout,
		readTimeout:  DefaultTimeout,
		writeTimeout: DefaultTimeout,
	}
}

func (c *ClientConfig) WithAddr(addr string) *ClientConfig {
	u, err := url.Parse(addr)
	if err != nil {
		c.err = multierror.Append(c.err, fmt.Errorf("invlid addr: %w", err))
		return c
	}

	c.net = u.Scheme
	c.addr = u.Host
	return c
}

func (c *ClientConfig) WithDialTimeout(timeout time.Duration) *ClientConfig {
	c.readTimeout = timeout
	return c
}

func (c *ClientConfig) WithReadTimeout(timeout time.Duration) *ClientConfig {
	c.readTimeout = timeout
	return c
}

func (c *ClientConfig) WithWriteTimeout(timeout time.Duration) *ClientConfig {
	c.readTimeout = timeout
	return c
}

func (c *ClientConfig) Build() *ClientConfig {
	return c
}

func (c *ClientConfig) Validate() error {
	if c.err != nil {
		return c.err
	}

	if c.addr == "" {
		return errors.New("upstream is not configured")
	}

	return nil
}
