package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/buglloc/deblocker/internal/httpcheck"
	"github.com/buglloc/deblocker/internal/services/dnssrv"
	"github.com/rs/zerolog/log"
	"net"
	"os"
)

func fatalf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, fmt.Sprintf("checker: %s\n", format), args...)
	os.Exit(1)
}

func main() {
	var directDev, vpnDev string
	flag.StringVar(&directDev, "direct-dev", "wlan0", "interface with direct traffic")
	flag.StringVar(&vpnDev, "vpn-dev", "eu", "interface with vpn traffic")
	flag.Parse()

	checker, err := httpcheck.NewChecker(
		httpcheck.NewCheckerConfig().
			WithDirectDev(directDev).
			WithVPNDev(vpnDev).
			Build(),
	)
	if err != nil {
		fatalf("unable to create checker: %v", err)
	}

	for _, fqdn := range flag.Args() {
		fmt.Println("check fqdn", fqdn)

		ips, err := net.LookupIP(fqdn)
		if err != nil {
			log.Error().
				Str("fqdn", fqdn).
				Err(err).
				Msg("resolve failed")
			continue
		}

		for _, ip := range ips {
			fmt.Printf("check fqdn %s with ip %s\n", fqdn, ip.String())
			ipKind := dnssrv.IPKindV4
			if len(ip) == net.IPv6len {
				ipKind = dnssrv.IPKindV6
			}

			blocked := checker.IsBlocked(context.Background(), fqdn, ip.String(), ipKind)
			fmt.Println(blocked)
		}
	}
}
