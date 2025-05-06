// Package quicssh_proxy provides a Caddy module for forwarding traffic to SSH servers over QUIC
package quicssh_proxy

import (
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(QuicSSHProxy{})
}

// QuicSSHProxy is a Caddy HTTP handler that forwards QUIC connections to SSH servers.
type QuicSSHProxy struct {
	// Address to listen on for QUIC connections
	ListenAddr string `json:"listen_addr,omitempty"`

	// TLS certificate and key files for QUIC
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// Whether to allow reverse tunneling
	AllowReverseTunnel bool `json:"allow_reverse_tunnel,omitempty"`

	// Whether to allow dynamic SOCKS5 proxy
	AllowSOCKS5 bool `json:"allow_socks5,omitempty"`

	// Restricted destinations (empty means no restrictions)
	RestrictDest []string `json:"restrict_dest,omitempty"`

	// Internal fields
	multiListener  *MultiListenerWrapper
	logger         *zap.Logger
	reverseTunnels map[string]string // map[hostname]destination
	tunnelsMu      sync.RWMutex
}

// Interface guards
var (
	_ caddy.Provisioner           = (*QuicSSHProxy)(nil)
	_ caddy.Validator             = (*QuicSSHProxy)(nil)
	_ caddyhttp.MiddlewareHandler = (*QuicSSHProxy)(nil)
	_ caddyfile.Unmarshaler       = (*QuicSSHProxy)(nil)
	_ caddy.App                   = (*QuicSSHProxy)(nil)
)

// CaddyModule returns the Caddy module information.
func (QuicSSHProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.quicssh_proxy",
		New: func() caddy.Module { return new(QuicSSHProxy) },
	}
}

// Provision sets up the module.
func (q *QuicSSHProxy) Provision(ctx caddy.Context) error {
	q.logger = ctx.Logger(q)
	q.reverseTunnels = make(map[string]string)

	// Start the listeners if an address is configured
	if q.ListenAddr != "" {
		if err := q.Start(); err != nil {
			return fmt.Errorf("starting listeners: %w", err)
		}
	}

	return nil
}

// Cleanup implements caddy.App.
func (q *QuicSSHProxy) Cleanup() error {
	return q.Stop()
}

// Validate ensures the module's configuration is valid.
func (q *QuicSSHProxy) Validate() error {
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (q *QuicSSHProxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "listen_addr":
				if !d.NextArg() {
					return d.ArgErr()
				}
				q.ListenAddr = d.Val()

			case "cert_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				q.CertFile = d.Val()

			case "key_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				q.KeyFile = d.Val()

			case "allow_reverse_tunnel":
				q.AllowReverseTunnel = true

			case "allow_socks5":
				q.AllowSOCKS5 = true

			case "restrict_dest":
				for d.NextArg() {
					q.RestrictDest = append(q.RestrictDest, d.Val())
				}
			}
		}
	}
	return nil
}
