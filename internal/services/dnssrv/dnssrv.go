package dnssrv

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/buglloc/certifi"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"net"
	"net/url"
)

type Server struct {
	upstream     string
	handler      IPHandler
	clientFilter ClientFilter
	srvCfg       *ServerConfig
	dnsc         *dns.Client
	closed       chan struct{}
	ctx          context.Context
	shutdownFn   context.CancelFunc
}

func NewServer(srvCfg *ServerConfig, clientCfg *ClientConfig) (*Server, error) {
	if err := srvCfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid server configuration: %w", err)
	}

	if err := clientCfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid client configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		upstream:     clientCfg.addr,
		handler:      srvCfg.handler,
		clientFilter: srvCfg.clientFilter,
		srvCfg:       srvCfg,
		dnsc: &dns.Client{
			Net: clientCfg.net,
			TLSConfig: &tls.Config{
				RootCAs: certifi.NewCertPool(),
			},
			DialTimeout:  clientCfg.dialTimeout,
			ReadTimeout:  clientCfg.readTimeout,
			WriteTimeout: clientCfg.writeTimeout,
		},
		closed:     make(chan struct{}),
		ctx:        ctx,
		shutdownFn: cancel,
	}, nil
}

func (s *Server) ListenAndServe() error {
	defer close(s.closed)

	g, ctx := errgroup.WithContext(s.ctx)
	shutdownFuncs := make([]func() error, len(s.srvCfg.addrs))
	for i, addr := range s.srvCfg.addrs {
		i := i
		addr := addr

		g.Go(func() error {
			srv := s.newServer(addr)
			shutdownFuncs[i] = srv.Shutdown

			log.Info().
				Str("net", srv.Net).
				Str("addr", srv.Addr).
				Msg("start DNS listening")
			return srv.ListenAndServe()
		})
	}

	g.Go(func() error {
		<-ctx.Done()
		for _, fn := range shutdownFuncs {
			if err := fn(); err != nil {
				log.Warn().Err(err).Msg("shutdown failed")
			}
		}
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

func (s *Server) srvHandler(w dns.ResponseWriter, r *dns.Msg) {
	rsp, _, err := s.dnsc.Exchange(r, s.upstream)
	if err != nil {
		log.Error().
			Str("req", r.String()).
			Err(err).
			Msg("request failed")
		_ = w.Close()
		return
	}

	if s.clientFilter == nil || s.clientFilter(clientIP(w.RemoteAddr())) {
		s.processHandler(rsp, r)
	}

	_ = w.WriteMsg(rsp)
}

func (s *Server) processHandler(rsp, req *dns.Msg) {
	if s.handler == nil {
		return
	}

	if req.Opcode != dns.OpcodeQuery {
		return
	}

	var fqdn string
	for _, rr := range req.Question {
		switch rr.Qtype {
		case dns.TypeAAAA, dns.TypeA:
		default:
			continue
		}

		fqdn = rr.Name
		break
	}

	for _, rr := range rsp.Answer {
		ttl := rr.Header().Ttl
		if ttl < 90 {
			ttl = 90
		}

		switch v := rr.(type) {
		case *dns.A:
			s.handler(RR{
				FQDN: fqdn,
				Kind: IPKindV4,
				IP:   v.A,
				TTL:  rr.Header().Ttl,
			})
		case *dns.AAAA:
			s.handler(RR{
				FQDN: fqdn,
				Kind: IPKindV4,
				IP:   v.AAAA,
				TTL:  rr.Header().Ttl,
			})
		}
	}
}

func (s *Server) newServer(addr *url.URL) *dns.Server {
	return &dns.Server{
		Net:           addr.Scheme,
		Addr:          addr.Host,
		Handler:       dns.HandlerFunc(s.srvHandler),
		MaxTCPQueries: s.srvCfg.maxTCPQueries,
		ReadTimeout:   s.srvCfg.readTimeout,
		WriteTimeout:  s.srvCfg.writeTimeout,
	}
}

func clientIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	default:
		return net.IPv4zero
	}
}
