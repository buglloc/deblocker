package deblocker

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/buglloc/deblocker/internal/config"
	"github.com/buglloc/deblocker/internal/services/bgpsrv"
	"github.com/buglloc/deblocker/internal/services/dnssrv"
)

type Server struct {
	bgp        *bgpsrv.Server
	dns        *dnssrv.Server
	siteLord   *SiteLord
	closed     chan struct{}
	ctx        context.Context
	shutdownFn context.CancelFunc
}

func NewServer(cfg *config.Config) (*Server, error) {
	srv := &Server{
		closed: make(chan struct{}),
	}

	var err error
	srv.bgp, err = bgpsrv.NewServer(
		bgpsrv.NewServerConfig().
			WithListenPort(cfg.BGP.ListenPort).
			WithListenAddr(cfg.BGP.ListenAddrs...).
			WithRouterID(cfg.BGP.RouterID).
			WithRouterASN(cfg.BGP.RouterASN).
			WithPeerASN(cfg.BGP.PeerASN).
			WithPeerAuthPassword(cfg.BGP.PeerAuthPassword).
			WithPeerNet(cfg.BGP.PeerNets...).
			WithNextHopIPv4(cfg.BGP.NextHopIPv4).
			WithNextHopIPv6(cfg.BGP.NextHopIPv6).
			Build(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create bgp server: %w", err)
	}

	srv.siteLord, err = NewSiteLord(srv.bgp, cfg.Checker)
	if err != nil {
		return nil, fmt.Errorf("unable to create site lord: %w", err)
	}

	srv.dns, err = dnssrv.NewServer(
		dnssrv.NewServerConfig().
			WithAddrs(cfg.DNS.Server.Addrs...).
			WithObservableNets(cfg.DNS.ObservableNets...).
			WithMaxTCPQueries(cfg.DNS.Server.MaxTCPQueries).
			WithReadTimeout(cfg.DNS.Server.ReadTimeout).
			WithWriteTimeout(cfg.DNS.Server.WriteTimeout).
			WithHandler(srv.siteLord.onResolvedIP).Build(),
		dnssrv.NewClientConfig().
			WithAddr(cfg.DNS.Client.Addr).
			WithDialTimeout(cfg.DNS.Client.DialTimeout).
			WithReadTimeout(cfg.DNS.Client.ReadTimeout).
			WithWriteTimeout(cfg.DNS.Client.WriteTimeout).
			Build(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create dns server: %w", err)
	}

	srv.ctx, srv.shutdownFn = context.WithCancel(context.Background())
	return srv, nil
}

func (s *Server) ListenAndServe() error {
	defer close(s.closed)

	g, ctx := errgroup.WithContext(s.ctx)
	g.Go(func() error {
		s.siteLord.Start()
		return nil
	})

	g.Go(func() error {
		if err := s.bgp.ListenAndServe(); err != nil {
			return fmt.Errorf("unable to listen BGP server: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := s.dns.ListenAndServe(); err != nil {
			return fmt.Errorf("unable to listen DNS server: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		<-ctx.Done()
		_ = s.dns.Shutdown(context.Background())
		_ = s.siteLord.Shutdown(context.Background())
		_ = s.bgp.Shutdown(context.Background())
		return nil
	})

	return g.Wait()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownFn()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return nil
	}
}
