package bgpsrv

import (
	"context"
	"fmt"
	"net"
	"strings"

	bgpapi "github.com/osrg/gobgp/v3/api"
	bgpsrv "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/rs/zerolog/log"
	apb "google.golang.org/protobuf/types/known/anypb"

	"github.com/buglloc/deblocker/internal/services/bgpsrv/bgpdef"
)

type Server struct {
	bgpSrv     *bgpsrv.BgpServer
	cfg        *ServerConfig
	closed     chan struct{}
	ctx        context.Context
	shutdownFn context.CancelFunc
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		bgpSrv:     bgpsrv.NewBgpServer(),
		cfg:        cfg,
		closed:     make(chan struct{}),
		ctx:        ctx,
		shutdownFn: cancel,
	}, nil
}

func (s *Server) ListenAndServe() error {
	defer close(s.closed)

	go s.bgpSrv.Serve()
	defer s.bgpSrv.Stop()

	err := s.bgpSrv.StartBgp(s.ctx, &bgpapi.StartBgpRequest{
		Global: &bgpapi.Global{
			Asn:             s.cfg.routerASN,
			RouterId:        s.cfg.routerID,
			ListenPort:      s.cfg.port,
			ListenAddresses: s.cfg.addrs,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to start bpg srv: %w", err)
	}
	log.Info().
		Uint32("router_asn", s.cfg.routerASN).
		Str("router_id", s.cfg.routerID).
		Int32("port", s.cfg.port).
		Str("addrs", strings.Join(s.cfg.addrs, ",")).
		Msg("bgp server started")

	err = s.bgpSrv.AddPeerGroup(s.ctx, &bgpapi.AddPeerGroupRequest{
		PeerGroup: &bgpapi.PeerGroup{
			Conf: &bgpapi.PeerGroupConf{
				PeerGroupName: "clients",
				AuthPassword:  s.cfg.peerAuthPassword,
				PeerAsn:       s.cfg.peerASN,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("unable to add peer group: %w", err)
	}
	log.Info().
		Str("group_name", "clients").
		Uint32("peer_asn", s.cfg.peerASN).
		Msg("added peer group")

	for _, prefix := range s.cfg.peerNets {
		err = s.bgpSrv.AddDynamicNeighbor(s.ctx, &bgpapi.AddDynamicNeighborRequest{
			DynamicNeighbor: &bgpapi.DynamicNeighbor{
				Prefix:    prefix,
				PeerGroup: "clients",
			},
		})
		if err != nil {
			return fmt.Errorf("unable to add dynamic neighbor %q: %w", prefix, err)
		}

		log.Info().
			Str("group_name", "clients").
			Str("prefix", prefix).
			Msg("added dynamic neighbor")
	}

	<-s.ctx.Done()
	return nil
}

func (s *Server) UpsertIPv4Net(ipnet net.IPNet) error {
	if exists, _ := s.isNetExists(ipnet, bgpdef.V4Family); exists {
		return nil
	}

	bgpPath, err := s.newIPv4Path(ipnet)
	if err != nil {
		return fmt.Errorf("unable to create ipv4 path: %w", err)
	}

	_, err = s.bgpSrv.AddPath(context.Background(), &bgpapi.AddPathRequest{
		Path: bgpPath,
	})
	if err != nil {
		return fmt.Errorf("add path: %w", err)
	}
	return err
}

func (s *Server) DeleteIPv4Net(ipnet net.IPNet) error {
	bgpPath, err := s.newIPv4Path(ipnet)
	if err != nil {
		return fmt.Errorf("unable to create ipv4 path: %w", err)
	}

	return s.bgpSrv.DeletePath(s.ctx, &bgpapi.DeletePathRequest{
		TableType: bgpapi.TableType_LOCAL,
		Family:    bgpdef.V6Family,
		Path:      bgpPath,
	})
}

func (s *Server) UpsertIPv6Net(ipnet net.IPNet) error {
	if exists, _ := s.isNetExists(ipnet, bgpdef.V6Family); exists {
		return nil
	}

	bgpPath, err := s.newIPv6Path(ipnet)
	if err != nil {
		return fmt.Errorf("unable to create ipv6 path: %w", err)
	}

	_, err = s.bgpSrv.AddPath(context.Background(), &bgpapi.AddPathRequest{
		Path: bgpPath,
	})
	if err != nil {
		return fmt.Errorf("add path: %w", err)
	}

	return nil
}

func (s *Server) DeleteIPv6Net(ipnet net.IPNet) error {
	bgpPath, err := s.newIPv6Path(ipnet)
	if err != nil {
		return fmt.Errorf("unable to create ipv6 path: %w", err)
	}

	return s.bgpSrv.DeletePath(s.ctx, &bgpapi.DeletePathRequest{
		TableType: bgpapi.TableType_LOCAL,
		Family:    bgpdef.V6Family,
		Path:      bgpPath,
	})
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

func (s *Server) isNetExists(ipnet net.IPNet, family *bgpapi.Family) (bool, error) {
	var exists bool
	err := s.bgpSrv.ListPath(
		s.ctx,
		&bgpapi.ListPathRequest{
			TableType: bgpapi.TableType_LOCAL,
			Prefixes: []*bgpapi.TableLookupPrefix{
				{
					Prefix: ipnet.String(),
					Type:   bgpapi.TableLookupPrefix_EXACT,
				},
			},
			Family: family,
		},
		func(destination *bgpapi.Destination) {
			exists = true
		},
	)
	return exists, err
}

func (s *Server) newIPv4Path(ipnet net.IPNet) (*bgpapi.Path, error) {
	nlri, err := ipNetToNLRI(ipnet)
	if err != nil {
		return nil, fmt.Errorf("create ip prefix: %w", err)
	}

	attrNextHop, err := apb.New(&bgpapi.NextHopAttribute{
		NextHop: s.cfg.nextHopIPv4,
	})
	if err != nil {
		return nil, fmt.Errorf("create next hop: %w", err)
	}

	return &bgpapi.Path{
		Family: bgpdef.V4Family,
		Nlri:   nlri,
		Pattrs: []*apb.Any{
			bgpdef.OriginAttribute,
			attrNextHop,
		},
	}, nil
}

func (s *Server) newIPv6Path(ipnet net.IPNet) (*bgpapi.Path, error) {
	nlri, err := ipNetToNLRI(ipnet)
	if err != nil {
		return nil, fmt.Errorf("create ip prefix: %w", err)
	}

	nlriAttr, err := apb.New(&bgpapi.MpReachNLRIAttribute{
		Family:   bgpdef.V6Family,
		NextHops: []string{s.cfg.nextHopIPv6},
		Nlris:    []*apb.Any{nlri},
	})
	if err != nil {
		return nil, fmt.Errorf("create mp reach NLRI attr: %w", err)
	}

	return &bgpapi.Path{
		Family: bgpdef.V6Family,
		Nlri:   nlri,
		Pattrs: []*apb.Any{
			bgpdef.OriginAttribute,
			nlriAttr,
			bgpdef.CommunitiesAttribute,
		},
	}, nil
}

func ipNetToNLRI(ipnet net.IPNet) (*apb.Any, error) {
	prefixLen, _ := ipnet.Mask.Size()
	return apb.New(&bgpapi.IPAddressPrefix{
		Prefix:    ipnet.IP.String(),
		PrefixLen: uint32(prefixLen),
	})
}
