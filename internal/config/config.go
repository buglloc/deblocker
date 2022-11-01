package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type DNSServer struct {
	Addrs         []string      `yaml:"addrs"`
	MaxTCPQueries int           `yaml:"max_tcp_queries"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
}

type DNSClient struct {
	Addr         string        `yaml:"addr"`
	DialTimeout  time.Duration `yaml:"dial_timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type DNS struct {
	Server         DNSServer `yaml:"server"`
	Client         DNSClient `yaml:"client"`
	ObservableNets []string  `yaml:"observable_nets"`
}

type BGP struct {
	ListenPort       int32    `yaml:"listen_port"`
	ListenAddrs      []string `yaml:"listen_addrs"`
	RouterID         string   `yaml:"router_id"`
	RouterASN        uint32   `yaml:"router_asn"`
	PeerASN          uint32   `yaml:"peer_asn"`
	PeerAuthPassword string   `yaml:"peer_auth_password"`
	PeerNets         []string `yaml:"peer_nets"`
	NextHopIPv4      string   `yaml:"next_hop_v4"`
	NextHopIPv6      string   `yaml:"next_hop_v6"`
}

type Checker struct {
	DirectDev     string        `yaml:"direct_dev"`
	VPNDev        string        `yaml:"vpn_dev"`
	Concurrency   int           `yaml:"concurrency"`
	QueueSize     int           `yaml:"queue_size"`
	IPHistorySize int64         `yaml:"ip_history_size"`
	IPHistoryTTL  time.Duration `yaml:"ip_history_ttl"`
	DecisionsSize int64         `yaml:"decisions_size"`
	DecisionsTTL  time.Duration `yaml:"decisions_ttl"`
	VPNSitesSize  int64         `yaml:"vpn_sites_size"`
	VPNSitesTTL   time.Duration `yaml:"vpn_sites_ttl"`
	RecheckPeriod time.Duration `yaml:"recheck_period"`
	DirectDomains []string      `yaml:"direct_domains"`
	VPNDomains    []string      `yaml:"vpn_domains"`
}

type Config struct {
	Debug   bool    `yaml:"debug"`
	DNS     DNS     `yaml:"dns"`
	BGP     BGP     `yaml:"bgp"`
	Checker Checker `yaml:"checker"`
}

func LoadConfig(configs ...string) (*Config, error) {
	out := &Config{
		Debug: true,
		DNS: DNS{
			Server: DNSServer{
				Addrs: []string{
					"tcp://:53",
					"udp://:53",
				},
				MaxTCPQueries: -1,
				ReadTimeout:   2 * time.Second,
				WriteTimeout:  2 * time.Second,
			},
			Client: DNSClient{
				Addr:         "tcp://1.1.1.1:53",
				DialTimeout:  2 * time.Second,
				ReadTimeout:  2 * time.Second,
				WriteTimeout: 2 * time.Second,
			},
		},
		BGP: BGP{
			ListenPort:       179,
			RouterID:         "1.3.3.7",
			RouterASN:        65543,
			PeerASN:          65542,
			PeerAuthPassword: os.Getenv("BGP_PEER_AUTH_PASSWORD"),
			PeerNets: []string{
				"0.0.0.0/0",
				"::/0",
			},
			NextHopIPv4: "87.250.250.242",
			NextHopIPv6: "2a02:6b8::2:242",
		},
		Checker: Checker{
			Concurrency:   32,
			QueueSize:     1024,
			IPHistorySize: 32384,
			IPHistoryTTL:  10 * time.Minute,
			DecisionsSize: 129536,
			DecisionsTTL:  30 * time.Minute,
			DirectDomains: []string{
				".ru",
			},
			VPNSitesSize:  32384,
			VPNSitesTTL:   24 * 7 * time.Hour,
			RecheckPeriod: 30 * time.Minute,
		},
	}

	if len(configs) == 0 {
		return out, nil
	}

	for _, cfgPath := range configs {
		err := func() error {
			f, err := os.Open(cfgPath)
			if err != nil {
				return fmt.Errorf("unable to open config file: %w", err)
			}
			defer func() { _ = f.Close() }()

			if err := yaml.NewDecoder(f).Decode(&out); err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}

			return nil
		}()
		if err != nil {
			return nil, fmt.Errorf("unable to load config %q: %w", cfgPath, err)
		}
	}

	return out, nil
}
