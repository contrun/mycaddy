package quicsshproxy

import (
	"context"
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
	"github.com/quic-go/quic-go"
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

// Start starts the QUIC listener
func (q *QuicSSHProxy) Start() error {
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

	// Start QUIC listener
	listener, err := quic.ListenAddr(q.ListenAddr, tlsConfig, nil)
	if err != nil {
		return fmt.Errorf("starting QUIC listener: %w", err)
	}
	q.listener = listener

	// Start accepting connections
	go q.acceptLoop()

	return nil
}

// Stop stops the QUIC listener
func (q *QuicSSHProxy) Stop() error {
	if q.listener != nil {
		return q.listener.Close()
	}
	return nil
}

// acceptLoop accepts and handles QUIC connections
func (q *QuicSSHProxy) acceptLoop() {
	ctx := context.Background()
	for {
		session, err := q.listener.Accept(ctx)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // Listener closed, exit loop
			}
			q.logger.Error("accepting QUIC connection", zap.Error(err))
			continue
		}

		go q.handleSession(ctx, session)
	}
}

// handleSession processes a QUIC session
func (q *QuicSSHProxy) handleSession(ctx context.Context, session quic.Connection) {
	defer session.CloseWithError(0, "session closed")

	// Extract SNI from connection for destination routing
	tlsInfo := session.ConnectionState().TLS
	serverName := tlsInfo.ServerName

	// Check if this is a connection to a reverse tunnel
	q.tunnelsMu.RLock()
	dest, ok := q.reverseTunnels[serverName]
	q.tunnelsMu.RUnlock()

	if ok {
		q.logger.Info("routing to reverse tunnel",
			zap.String("server_name", serverName),
			zap.String("destination", dest))
		q.handleReverseConnection(ctx, session, dest)
		return
	}

	// This is a direct connection, handle the stream
	for {
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // Session closed
			}
			q.logger.Error("accepting stream", zap.Error(err))
			return
		}

		// Handle each stream in a goroutine
		go q.handleDirectStream(ctx, stream, serverName)
	}
}

// handleDirectStream forwards a QUIC stream to the destination
func (q *QuicSSHProxy) handleDirectStream(ctx context.Context, stream quic.Stream, dest string) {
	defer stream.Close()

	// Check if the destination is allowed
	if !q.isDestinationAllowed(dest) {
		q.logger.Warn("destination not allowed", zap.String("destination", dest))
		return
	}

	// Connect to the destination
	conn, err := net.Dial("tcp", dest)
	if err != nil {
		q.logger.Error("dialing destination", zap.Error(err), zap.String("destination", dest))
		return
	}
	defer conn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
		stream.CancelRead(0)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
		conn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}
