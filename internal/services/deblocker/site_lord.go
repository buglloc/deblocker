package deblocker

import (
	"bufio"
	"context"
	"fmt"
	"github.com/buglloc/deblocker/internal/config"
	"github.com/buglloc/deblocker/internal/httpcheck"
	"github.com/buglloc/deblocker/internal/services/bgpsrv"
	"github.com/buglloc/deblocker/internal/services/dnssrv"
	"github.com/karlseguin/ccache/v3"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Decision uint8

const (
	DecisionNone Decision = iota
	DecisionDirect
	DecisionVPN
	DecisionCheck
)

type siteRR struct {
	dnssrv.RR
	Site string
}

type SiteLord struct {
	bgp           *bgpsrv.Server
	hck           *httpcheck.Checker
	concurrency   int
	decisions     *ccache.Cache[Decision]
	decisionsTTL  time.Duration
	ipsHistory    *ccache.LayeredCache[dnssrv.RR]
	ipsHistoryTTL time.Duration
	toCheck       chan siteRR
	directDomains []string
	vpnDomains    []string
	closed        chan struct{}
	ctx           context.Context
	shutdownFn    context.CancelFunc
}

func NewSiteLord(bgp *bgpsrv.Server, cfg config.Checker) (*SiteLord, error) {
	hck, err := httpcheck.NewChecker(
		httpcheck.NewCheckerConfig().
			WithDirectDev(cfg.DirectDev).
			WithVPNDev(cfg.VPNDev).
			Build(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create http checker: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := &SiteLord{
		bgp:           bgp,
		hck:           hck,
		concurrency:   cfg.Concurrency,
		toCheck:       make(chan siteRR, cfg.QueueSize),
		closed:        make(chan struct{}),
		decisionsTTL:  cfg.DecisionsTTL,
		ipsHistoryTTL: cfg.IPHistoryTTL,
		ctx:           ctx,
		shutdownFn:    cancel,
	}

	out.decisions = ccache.New(
		ccache.Configure[Decision]().
			MaxSize(cfg.DecisionsSize),
	)

	out.ipsHistory = ccache.Layered(
		ccache.Configure[dnssrv.RR]().
			MaxSize(cfg.IPHistorySize).
			OnDelete(func(item *ccache.Item[dnssrv.RR]) {
				out.deleteRR(item.Value())
			}),
	)

	if err := out.loadDomains(cfg.DirectDomains, cfg.VPNDomains); err != nil {
		out.decisions.Stop()
		out.ipsHistory.Stop()
		cancel()
		return nil, fmt.Errorf("unable to load domains: %w", err)
	}

	return out, nil
}

func (l *SiteLord) Start() {
	defer close(l.closed)

	var wg sync.WaitGroup
	wg.Add(l.concurrency)

	for i := 0; i < l.concurrency; i++ {
		go func() {
			l.checkWorker(l.toCheck)
			wg.Done()
		}()
	}
	wg.Wait()
}

func (l *SiteLord) Shutdown(ctx context.Context) error {
	l.shutdownFn()

	defer func() {
		l.ipsHistory.Stop()
		l.decisions.Stop()
	}()

	close(l.toCheck)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.closed:
		return nil
	}
}

func (l *SiteLord) checkWorker(toCheck <-chan siteRR) {
	for rr := range toCheck {
		blocked := l.hck.IsBlocked(l.ctx, rr.FQDN, rr.IP.String(), rr.Kind)
		var decision Decision
		if blocked {
			decision = DecisionVPN
		} else {
			decision = DecisionDirect
		}

		l.decisions.Set(rr.Site, decision, l.decisionsTTL)
		l.updateBGPRecords(rr.Site, !blocked)
	}
}

func (l *SiteLord) deleteRR(rr dnssrv.RR) {
	var err error
	switch rr.Kind {
	case dnssrv.IPKindV4:
		err = l.bgp.DeleteIPv4Net(ipv4ToNet(rr.IP))
	case dnssrv.IPKindV6:
		err = l.bgp.DeleteIPv6Net(ipv6ToNet(rr.IP))
	default:
		err = fmt.Errorf("unsupported ip kind for fqdn %q: %s", rr.FQDN, rr.Kind)
	}
	if err != nil {
		log.Error().Str("fqdn", rr.FQDN).Str("ip", rr.IP.String()).Err(err).Msg("unable to delete")
	} else {
		log.Info().Str("fqdn", rr.FQDN).Str("ip", rr.IP.String()).Err(err).Msg("delete ip from bgp")
	}
}

func (l *SiteLord) upsertRR(rr dnssrv.RR) {
	var err error
	switch rr.Kind {
	case dnssrv.IPKindV4:
		err = l.bgp.UpsertIPv4Net(ipv4ToNet(rr.IP))
	case dnssrv.IPKindV6:
		err = l.bgp.UpsertIPv6Net(ipv6ToNet(rr.IP))
	default:
		err = fmt.Errorf("unsupported ip kind for fqdn %q: %s", rr.FQDN, rr.Kind)
	}
	if err != nil {
		log.Error().Str("fqdn", rr.FQDN).Str("ip", rr.IP.String()).Err(err).Msg("unable to upsert to bgp")
	} else {
		log.Info().Str("fqdn", rr.FQDN).Str("ip", rr.IP.String()).Err(err).Msg("added ip to bgp")
	}
}

func (l *SiteLord) updateBGPRecords(site string, delete bool) {
	l.ipsHistory.ForEachFunc(site, func(key string, item *ccache.Item[dnssrv.RR]) bool {
		rr := item.Value()
		if item.Expired() || delete {
			l.deleteRR(rr)
			return true
		}

		l.upsertRR(rr)
		return true
	})
}

func (l *SiteLord) loadDomains(directPath, vpnPath string) error {
	doLoad := func(filepath string) ([]string, error) {
		f, err := os.Open(filepath)
		if err != nil && os.IsNotExist(err) {
			return nil, nil
		}

		scanner := bufio.NewScanner(f)
		var out []string
		for scanner.Scan() {
			fqdn := strings.Trim(scanner.Text(), ".")
			out = append(out, fmt.Sprintf(".%s.", fqdn))
		}

		return out, scanner.Err()
	}

	var err error
	l.directDomains, err = doLoad(directPath)
	if err != nil {
		return fmt.Errorf("unable to load direct domains: %w", err)
	}

	l.vpnDomains, err = doLoad(vpnPath)
	if err != nil {
		return fmt.Errorf("unable to load vpn domains: %w", err)
	}

	return nil
}

func (l *SiteLord) onResolvedIP(rr dnssrv.RR) {
	site, err := siteFromFqdn(rr.FQDN)
	if err != nil {
		log.Warn().Str("fqdn", rr.FQDN).Err(err).Msg("unable to get site from fqdn")
	} else {
		ipKey := rr.FQDN + rr.IP.String()
		if item := l.ipsHistory.GetWithoutPromote(site, ipKey); item == nil {
			l.ipsHistory.Set(site, ipKey, rr, l.ipsHistoryTTL)
		} else {
			item.Extend(l.ipsHistoryTTL)
		}
	}

	decision, err := l.fqdnDecision(rr.FQDN, site)
	if err != nil {
		log.Error().
			Str("fqdn", rr.FQDN).
			Str("resolved_ip", rr.IP.String()).
			Err(err).
			Msg("unable to make decision")
		return
	}

	log.Debug().Uint8("des", uint8(decision)).Str("fqdn", rr.FQDN).Msg("des")
	switch decision {
	case DecisionDirect:
		return
	case DecisionCheck:
		l.toCheck <- siteRR{
			RR:   rr,
			Site: site,
		}
		return
	case DecisionVPN:
		switch rr.Kind {
		case dnssrv.IPKindV4:
			err = l.bgp.UpsertIPv4Net(net.IPNet{
				IP:   rr.IP,
				Mask: net.CIDRMask(32, 8*net.IPv4len),
			})
		case dnssrv.IPKindV6:
			err = l.bgp.UpsertIPv6Net(net.IPNet{
				IP:   rr.IP,
				Mask: net.CIDRMask(32, 8*net.IPv6len),
			})
		default:
			err = fmt.Errorf("unsupported ip kind: %s", rr.Kind)
			return
		}

		if err != nil {
			log.Error().
				Str("fqdn", rr.FQDN).
				Str("resolved_ip", rr.IP.String()).
				Err(err).
				Msg("unable to upsert IP to BGP")
			return
		}

		log.Debug().
			Str("fqdn", rr.FQDN).
			Str("resolved_ip", rr.IP.String()).
			Msg("added IP")
		return
	}
}

func (l *SiteLord) fqdnDecision(fqdn, site string) (Decision, error) {
	switch {
	case containsFqdn(l.directDomains, fqdn):
		return DecisionDirect, nil
	case containsFqdn(l.vpnDomains, fqdn):
		return DecisionVPN, nil
	case site == "":
		// can't properly work w/o site
		return DecisionDirect, nil
	}

	cached := l.decisions.Get(site)
	if cached == nil {
		return DecisionCheck, nil
	}

	if cached.Expired() {
		return DecisionCheck, nil
	}

	return cached.Value(), nil
}

func containsFqdn(fqdnSlice []string, fqdn string) bool {
	for _, f := range fqdnSlice {
		if fqdn == f || strings.HasSuffix(fqdn, f) {
			return true
		}
	}

	return false
}

func siteFromFqdn(fqdn string) (string, error) {
	u, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(fqdn, "."))
	if err != nil {
		return "", err
	}

	return u + ".", nil
}

func ipv4ToNet(addr net.IP) net.IPNet {
	return net.IPNet{
		IP:   addr,
		Mask: net.CIDRMask(32, 8*net.IPv4len),
	}
}

func ipv6ToNet(addr net.IP) net.IPNet {
	return net.IPNet{
		IP:   addr,
		Mask: net.CIDRMask(32, 8*net.IPv6len),
	}
}
