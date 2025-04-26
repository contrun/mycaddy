package quicsshproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// generateTLSConfig creates a TLS config with a self-signed certificate
func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"QuicSSH Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quicssh"},
	}, nil
}

// isDestinationAllowed checks if the destination is allowed based on the restrictions
func (q *QuicSSHProxy) isDestinationAllowed(dest string) bool {
	if len(q.RestrictDest) == 0 {
		return true // No restrictions
	}

	for _, allowed := range q.RestrictDest {
		if dest == allowed {
			return true
		}
	}

	return false
}

// handleForward handles a forward tunnel request (like SSH -L)
func (q *QuicSSHProxy) handleForward(conn *websocket.Conn, r *http.Request) error {
	// Parse target from the request
	target := r.URL.Query().Get("target")
	if target == "" {
		conn.Close(websocket.StatusCode(4000), "missing target parameter")
		return nil
	}

	// Check if the destination is allowed
	if !q.isDestinationAllowed(target) {
		conn.Close(websocket.StatusCode(4003), "destination not allowed")
		return nil
	}

	// Create a websocket connection wrapper
	wsConn := NewWebSocketConnWrapper(conn, target)

	// Handle the connection
	q.handleConnection(wsConn)

	return nil
}

// handleReverse handles a reverse tunnel registration (like SSH -R)
func (q *QuicSSHProxy) handleReverse(conn *websocket.Conn, r *http.Request) error {
	hostname := r.URL.Query().Get("hostname")
	target := r.URL.Query().Get("target")

	if hostname == "" || target == "" {
		conn.Close(websocket.StatusCode(4000), "missing hostname or target parameters")
		return nil
	}

	// Register the reverse tunnel
	q.tunnelsMu.Lock()
	q.reverseTunnels[hostname] = target
	q.tunnelsMu.Unlock()

	q.logger.Info("registered reverse tunnel",
		zap.String("hostname", hostname),
		zap.String("target", target))

	// Keep connection open until client disconnects
	ctx := conn.CloseRead(context.Background())
	<-ctx.Done()

	// Unregister the tunnel when the client disconnects
	q.tunnelsMu.Lock()
	delete(q.reverseTunnels, hostname)
	q.tunnelsMu.Unlock()

	q.logger.Info("unregistered reverse tunnel", zap.String("hostname", hostname))
	return nil
}

// handleSocks implements a SOCKS5 proxy (like SSH -D)
func (q *QuicSSHProxy) handleSocks(conn *websocket.Conn, r *http.Request) error {
	// Create a websocket connection wrapper
	wsConn := NewWebSocketConnWrapper(conn, "socks-proxy")

	// Handle the connection using our wrapper
	q.handleConnection(wsConn)

	return nil
}

// forwardWebSocketToTCP forwards data between a WebSocket connection and a TCP connection
func (q *QuicSSHProxy) forwardWebSocketToTCP(wsConn *websocket.Conn, tcpConn net.Conn) {
	defer tcpConn.Close()

	// Create a context that gets canceled when the WebSocket closes
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// WebSocket -> TCP
	go func() {
		defer wg.Done()
		defer cancel()

		for {
			_, message, err := wsConn.Read(ctx)
			if err != nil {
				return
			}

			_, err = tcpConn.Write(message)
			if err != nil {
				return
			}
		}
	}()

	// TCP -> WebSocket
	go func() {
		defer wg.Done()
		defer cancel()

		buffer := make([]byte, 32*1024)
		for {
			n, err := tcpConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					q.logger.Error("reading from TCP", zap.Error(err))
				}
				return
			}

			err = wsConn.Write(ctx, websocket.MessageBinary, buffer[:n])
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
	wsConn.Close(websocket.StatusNormalClosure, "")
}

// handleReverseConnection handles a connection to a reverse tunnel
func (q *QuicSSHProxy) handleReverseConnection(ctx context.Context, session quic.Connection, dest string) {
	// Accept streams and forward them to the destination
	for {
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // Session closed
			}
			q.logger.Error("accepting stream for reverse tunnel", zap.Error(err))
			return
		}

		go q.handleDirectStream(ctx, stream, dest)
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
