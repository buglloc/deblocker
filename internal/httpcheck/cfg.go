package httpcheck

import (
	"errors"
	"fmt"
	"time"
)

type CheckerConfig struct {
	directDev string
	vpnDev    string
	timeout   time.Duration
}

func NewCheckerConfig() *CheckerConfig {
	return &CheckerConfig{
		timeout: 2 * time.Second,
	}
}

func (c *CheckerConfig) WithDirectDev(dev string) *CheckerConfig {
	c.directDev = dev
	return c
}

func (c *CheckerConfig) WithVPNDev(dev string) *CheckerConfig {
	c.vpnDev = dev
	return c
}

func (c *CheckerConfig) Build() *CheckerConfig {
	return c
}

func (c *CheckerConfig) Validate() error {
	if c.directDev == "" {
		return errors.New("VPM device must be set")
	}

	if err := checkDev(c.directDev); err != nil {
		return fmt.Errorf("invalid direct devive: %w", err)
	}

	if c.vpnDev == "" {
		return errors.New("vpn device must be set")
	}

	if err := checkDev(c.vpnDev); err != nil {
		return fmt.Errorf("invalid vpn devive: %w", err)
	}

	return nil
}
