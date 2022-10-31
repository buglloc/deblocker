package httpcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/buglloc/certifi"
	"github.com/buglloc/deblocker/internal/services/dnssrv"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"sync"
)

type Checker struct {
	cfg         *CheckerConfig
	resolver    *LocalResolver
	directHTTPc *http.Client
	vpnHTTPc    *http.Client
}

func NewChecker(cfg *CheckerConfig) (*Checker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	localRevolver := NewLocalResolver()
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = &tls.Config{
		RootCAs: certifi.NewCertPool(),
	}

	directTransport := httpTransport.Clone()
	directTransport.DialContext = newDialContext(cfg.directDev, localRevolver)

	vpnTransport := httpTransport.Clone()
	vpnTransport.DialContext = newDialContext(cfg.vpnDev, localRevolver)

	return &Checker{
		cfg:      cfg,
		resolver: localRevolver,
		directHTTPc: &http.Client{
			Timeout:   cfg.timeout,
			Transport: directTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		vpnHTTPc: &http.Client{
			Timeout:   cfg.timeout,
			Transport: vpnTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Checker) IsBlocked(ctx context.Context, fqdn, ip string, ipKind dnssrv.IPKind) bool {
	fqdn = c.resolverAdd(fqdn, ip, ipKind)
	defer c.resolver.Del(fqdn)
	uri := "https://" + fqdn

	doCheck := func() bool {
		var wg sync.WaitGroup
		wg.Add(2)

		var directOK bool
		go func() {
			defer wg.Done()

			ok, _ := c.checkFqdn(ctx, c.directHTTPc, uri)
			directOK = ok
		}()

		var vpnOK bool
		go func() {
			defer wg.Done()

			ok, _ := c.checkFqdn(ctx, c.vpnHTTPc, uri)
			vpnOK = ok
		}()

		wg.Wait()
		return !directOK && vpnOK
	}

	blocked := doCheck()
	if blocked {
		// recheck
		blocked = doCheck()
		if !blocked {
			log.Warn().Str("fqdn", fqdn).Str("ip", ip).Msg("flaky fqdn")
		}
	}

	return blocked
}

func (c *Checker) checkFqdn(ctx context.Context, httpc *http.Client, uri string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, uri, nil)
	if err != nil {
		return false, fmt.Errorf("unable to create new HTTP request: %w", err)
	}

	rsp, err := httpc.Do(req)
	if err != nil {
		return false, fmt.Errorf("unable to make http request: %w", err)
	}

	_, _ = io.CopyN(io.Discard, rsp.Body, 128<<10)
	_ = rsp.Body.Close()

	return rsp.StatusCode != http.StatusForbidden, nil
}

func (c *Checker) resolverAdd(fqdn, ip string, ipKind dnssrv.IPKind) string {
	switch ipKind {
	case dnssrv.IPKindV4:
		ip += ":443"
	case dnssrv.IPKindV6:
		ip = fmt.Sprintf("[%s]:443", ip)
	default:
		panic(fmt.Sprintf("unsupported ip kind: %s", ipKind))
	}

	return c.resolver.Add(fqdn, ip)
}
