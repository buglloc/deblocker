package httpcheck

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

const (
	HTTPTimeout   = 500 * time.Millisecond
	HTTPKeepAlive = 60 * time.Second
)

func checkDev(dev string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("unable to list network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Name != dev {
			continue
		}

		if iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("interface %q in not up", dev)
		}

		return nil
	}

	return fmt.Errorf("interface with name %q is not found", dev)
}

func bindToDeviceControl(dev string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var cerr error
		err := c.Control(func(fd uintptr) {
			cerr = syscall.BindToDevice(int(fd), dev)
		})

		if err != nil {
			return fmt.Errorf("socket Control: %w", err)
		}

		if cerr != nil {
			return fmt.Errorf("BindToDevice: %w", cerr)
		}

		return nil
	}
}

type dialContextFn func(ctx context.Context, network, addr string) (net.Conn, error)

func newDialContext(dev string, resolver *LocalResolver) dialContextFn {
	dialer := &net.Dialer{
		Timeout:   HTTPTimeout,
		KeepAlive: HTTPKeepAlive,
		Control:   bindToDeviceControl(dev),
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		addr, ok := resolver.Lookup(addr)
		if !ok {
			return nil, fmt.Errorf("unable to resolve addr: %s", addr)
		}

		return dialer.DialContext(ctx, network, addr)
	}
}
