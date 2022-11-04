package deblocker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/karlseguin/ccache/v3"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"

	"github.com/buglloc/deblocker/internal/config"
	"github.com/buglloc/deblocker/internal/httpcheck"
	"github.com/buglloc/deblocker/internal/services/bgpsrv"
	"github.com/buglloc/deblocker/internal/services/dnssrv"
)

type Decision uint8

const (
	DecisionNone Decision = iota
	DecisionDirect
	DecisionVPN
	DecisionDirectCheck
	DecisionVPNCheck
)

type siteRR struct {
	dnssrv.RR
	Site string
}

type VPNSite struct {
	mu           sync.Mutex
	blockedFqdns map[string]struct{}
}

type SiteLord struct {
	bgp           *bgpsrv.Server
	hck           *httpcheck.Checker
	concurrency   int
	vpnSites      *ccache.Cache[*VPNSite]
	vpnSitesTTL   time.Duration
	decisions     *ccache.Cache[Decision]
	decisionsTTL  time.Duration
	dnsCache      *ccache.LayeredCache[dnssrv.RR]
	dnsCacheTTL   time.Duration
	recheckPeriod time.Duration
	checkQueue    chan siteRR
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
		checkQueue:    make(chan siteRR, cfg.QueueSize),
		decisionsTTL:  cfg.DecisionsTTL,
		dnsCacheTTL:   cfg.IPHistoryTTL,
		vpnSitesTTL:   cfg.VPNSitesTTL,
		directDomains: normalizeDomains(cfg.DirectDomains),
		vpnDomains:    normalizeDomains(cfg.VPNDomains),
		recheckPeriod: cfg.RecheckPeriod,
		closed:        make(chan struct{}),
		ctx:           ctx,
		shutdownFn:    cancel,
	}

	out.vpnSites = ccache.New(
		ccache.Configure[*VPNSite]().
			MaxSize(cfg.IPHistorySize),
	)

	out.decisions = ccache.New(
		ccache.Configure[Decision]().
			MaxSize(cfg.VPNSitesSize),
	)

	out.dnsCache = ccache.Layered(
		ccache.Configure[dnssrv.RR]().
			MaxSize(cfg.IPHistorySize).
			OnDelete(func(item *ccache.Item[dnssrv.RR]) {
				out.deleteRR(item.Value())
			}),
	)

	return out, nil
}

func (l *SiteLord) Start() {
	defer close(l.closed)

	var wg sync.WaitGroup
	wg.Add(l.concurrency)

	for i := 0; i < l.concurrency; i++ {
		go func() {
			l.checkWorker(l.checkQueue)
			wg.Done()
		}()
	}

	go l.offlineWorker(l.recheckPeriod)
	wg.Wait()
}

func (l *SiteLord) Shutdown(ctx context.Context) error {
	l.shutdownFn()

	defer func() {
		l.dnsCache.Stop()
		l.decisions.Stop()
	}()

	close(l.checkQueue)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.closed:
		return nil
	}
}

func (l *SiteLord) checkWorker(toCheck <-chan siteRR) {
	for rr := range toCheck {
		ipStr := rr.IP.String()
		isBlocked, _ := l.hck.IsBlocked(l.ctx, rr.FQDN, ipStr, rr.Kind)
		isVPNSite := l.isVpnSiteCached(rr.Site)
		log.Debug().
			Str("site", rr.Site).
			Str("fqdn", rr.FQDN).
			Str("ip", ipStr).
			Bool("blocked", isBlocked).
			Bool("vpn_site", isVPNSite).
			Msg("checked")

		switch {
		case !isBlocked && !isVPNSite:
			l.decisions.Set(rr.Site, DecisionDirect, l.decisionsTTL)
		case isBlocked && !isVPNSite:
			l.updateBGPRecords(rr.Site, false)
			fallthrough
		default:
			cached, _ := l.vpnSites.Fetch(rr.Site, l.vpnSitesTTL, func() (*VPNSite, error) {
				log.Info().
					Str("source", "online_check").
					Str("site", rr.Site).
					Str("fqdn", rr.FQDN).
					Str("ip", ipStr).
					Msg("new blocked site detected")

				return &VPNSite{
					blockedFqdns: map[string]struct{}{},
				}, nil
			})
			vpnSite := cached.Value()
			vpnSite.mu.Lock()
			vpnSite.blockedFqdns[rr.FQDN] = struct{}{}
			vpnSite.mu.Unlock()
			l.decisions.Set(rr.Site, DecisionVPN, l.decisionsTTL)
		}
	}
}

func (l *SiteLord) offlineWorker(recheckPeriod time.Duration) {
	ticker := time.NewTicker(recheckPeriod)
	defer ticker.Stop()

	logger := log.With().Str("source", "offline_check").Logger()
	for {
		select {
		case <-l.closed:
			return
		case <-ticker.C:
		}

		l.vpnSites.ForEachFunc(func(site string, item *ccache.Item[*VPNSite]) bool {
			if item.Expired() {
				l.vpnSites.Delete(site)
				l.updateBGPRecords(site, true)
				return true
			}

			vpnSite := item.Value()
			vpnSite.mu.Lock()
			fqdns := make([]string, 0, len(vpnSite.blockedFqdns))
			for fqdn := range vpnSite.blockedFqdns {
				fqdns = append(fqdns, fqdn)
			}
			vpnSite.mu.Unlock()

			var siteBlocked bool
			for _, fqdn := range fqdns {
				var rrs []dnssrv.RR
				l.dnsCache.ForEachFunc(site, func(_ string, item *ccache.Item[dnssrv.RR]) bool {
					if !item.Expired() {
						rrs = append(rrs, item.Value())
					}

					return true
				})

				var isBlocked bool
				for _, rr := range rrs {
					ipStr := rr.IP.String()
					blocked, err := l.hck.IsBlocked(l.ctx, fqdn, ipStr, rr.Kind)
					if err != nil {
						logger.Warn().
							Str("fqdn", fqdn).
							Str("ip", ipStr).
							Err(err).
							Msg("unable to check blocked state")
					}

					if blocked {
						isBlocked = true
						break
					}
				}

				siteBlocked = siteBlocked || isBlocked
				if isBlocked {
					siteBlocked = true
				}
			}

			if !siteBlocked {
				logger.Info().
					Str("site", site).
					Msg("site is not blocked anymore and will be excluded from the VPN route")
				l.vpnSites.Delete(site)
				l.updateBGPRecords(site, true)
				return true
			}

			logger.Info().
				Str("site", site).
				Msg("site is still blocked, raise it's state TTL")
			item.Extend(l.vpnSitesTTL)
			return true
		})
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
	l.dnsCache.ForEachFunc(site, func(key string, item *ccache.Item[dnssrv.RR]) bool {
		rr := item.Value()
		if item.Expired() || delete {
			l.deleteRR(rr)
			return true
		}

		l.upsertRR(rr)
		return true
	})
}

func (l *SiteLord) onResolvedIP(rr dnssrv.RR) {
	site, err := siteFromFqdn(rr.FQDN)
	if err != nil {
		log.Warn().Str("fqdn", rr.FQDN).Err(err).Msg("unable to get site from fqdn")
	} else {
		ipKey := rr.FQDN + rr.IP.String()
		if item := l.dnsCache.GetWithoutPromote(site, ipKey); item == nil {
			l.dnsCache.Set(site, ipKey, rr, l.dnsCacheTTL)
		} else {
			item.Extend(l.dnsCacheTTL)
		}
	}

	switch l.fqdnDecision(rr.FQDN, site) {
	case DecisionDirect:
	case DecisionVPN:
		l.upsertRR(rr)
	case DecisionVPNCheck:
		l.upsertRR(rr)
		fallthrough
	case DecisionDirectCheck:
		l.checkQueue <- siteRR{
			RR:   rr,
			Site: site,
		}
		return
	}
}

func (l *SiteLord) fqdnDecision(fqdn, site string) Decision {
	switch {
	case containsFqdn(l.directDomains, fqdn):
		return DecisionDirect
	case containsFqdn(l.vpnDomains, fqdn):
		return DecisionVPN
	case site == "":
		// can't properly work w/o site
		return DecisionDirect
	}

	decision := DecisionDirectCheck
	if l.isVpnSiteCached(site) {
		decision = DecisionVPNCheck
	}

	cached := l.decisions.Get(fqdn)
	if cached == nil || cached.Expired() {
		return decision
	}

	return cached.Value()
}

func (l *SiteLord) isVpnSiteCached(site string) bool {
	return l.vpnSites.Get(site) != nil
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

func normalizeDomains(domains []string) []string {
	out := make([]string, len(domains))
	for i, domain := range domains {
		d := strings.Trim(domain, ".")
		out[i] = fmt.Sprintf(".%s.", d)
	}
	return out
}
