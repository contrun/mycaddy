// Package quicssh_proxy implements HTTP handlers for QUIC-SSH proxy
package quicssh_proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coder/websocket"
	"go.uber.org/zap"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (q *QuicSSHProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Check if this is a WebSocket upgrade request for our handler
	if strings.HasPrefix(r.URL.Path, "/quicssh") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return q.handleWebSocket(w, r)
	}

	// Not for us, pass to the next handler
	return next.ServeHTTP(w, r)
}

// handleWebSocket handles WebSocket connections for QUIC SSH proxy commands
func (q *QuicSSHProxy) handleWebSocket(w http.ResponseWriter, r *http.Request) error {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		q.logger.Error("websocket upgrade failed", zap.Error(err))
		return err
	}
	defer conn.Close(websocket.StatusInternalError, "connection closed")

	// Parse command from path (e.g., /quicssh/forward, /quicssh/reverse, /quicssh/socks)
	cmd := strings.TrimPrefix(r.URL.Path, "/quicssh/")

	switch cmd {
	case "forward":
		return q.handleForward(conn, r)
	case "reverse":
		if !q.AllowReverseTunnel {
			conn.Close(websocket.StatusPolicyViolation, "reverse tunneling not allowed")
			return nil
		}
		return q.handleReverse(conn, r)
	case "socks":
		if !q.AllowSOCKS5 {
			conn.Close(websocket.StatusPolicyViolation, "SOCKS5 proxy not allowed")
			return nil
		}
		return q.handleSocks(conn, r)
	default:
		conn.Close(websocket.StatusUnsupportedData, "unknown command")
		return nil
	}
}

// Start starts the listeners
func (q *QuicSSHProxy) Start() error {
	var listeners []ListenerWrapper

	// Create QUIC listener if an address is configured
	if q.ListenAddr != "" {
		// Generate or load TLS certificate
		var tlsConfig *tls.Config
		var err error

		if q.CertFile != "" && q.KeyFile != "" {
			// Load custom certificate
			cert, err := tls.LoadX509KeyPair(q.CertFile, q.KeyFile)
			if err != nil {
				return fmt.Errorf("loading TLS certificate: %w", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"quicssh"},
			}
		} else {
			// Generate self-signed certificate
			tlsConfig, err = generateTLSConfig()
			if err != nil {
				return fmt.Errorf("generating TLS config: %w", err)
			}
		}

		// Create QUIC listener wrapper
		quicListener, err := NewQUICListenerWrapper(q.ListenAddr, tlsConfig, q.logger)
		if err != nil {
			return err
		}
		listeners = append(listeners, quicListener)
	}

	// Create the multi-listener wrapper
	if len(listeners) > 0 {
		q.multiListener = NewMultiListenerWrapper(listeners, q.logger)
		q.multiListener.Start()

		// Start accepting connections
		go q.acceptLoop()
	}

	return nil
}

// Stop stops the listeners
func (q *QuicSSHProxy) Stop() error {
	if q.multiListener != nil {
		return q.multiListener.Close()
	}
	return nil
}

// acceptLoop accepts and handles connections
func (q *QuicSSHProxy) acceptLoop() {
	for {
		conn, err := q.multiListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // Listener closed, exit loop
			}
			q.logger.Error("accepting connection", zap.Error(err))
			continue
		}

		go q.handleConnection(conn)
	}
}

// handleConnection handles a connection
func (q *QuicSSHProxy) handleConnection(conn ConnWrapper) {
	defer conn.Close()

	var destination string

	// Determine the destination based on the connection type
	switch c := conn.(type) {
	case *QUICConnWrapper:
		// For QUIC connections, use the SNI as the destination
		serverName := c.GetServerName()

		// Check if this is a connection to a reverse tunnel
		q.tunnelsMu.RLock()
		dest, ok := q.reverseTunnels[serverName]
		q.tunnelsMu.RUnlock()

		if ok {
			q.logger.Info("routing to reverse tunnel",
				zap.String("server_name", serverName),
				zap.String("destination", dest))
			destination = dest
		} else {
			destination = serverName
		}

	case *WebSocketConnWrapper:
		// For WebSocket connections, the target is provided in the wrapper
		destination = c.GetTarget()

	default:
		q.logger.Error("unknown connection type", zap.String("type", fmt.Sprintf("%T", conn)))
		return
	}

	// Check if the destination is allowed
	if !q.isDestinationAllowed(destination) {
		q.logger.Warn("destination not allowed", zap.String("destination", destination))
		return
	}

	// Connect to the destination
	targetConn, err := net.Dial("tcp", destination)
	if err != nil {
		q.logger.Error("dialing destination", zap.Error(err), zap.String("destination", destination))
		return
	}
	defer targetConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
	}()

	wg.Wait()
}
