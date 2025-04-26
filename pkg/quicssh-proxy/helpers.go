package quicsshproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
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

	// Create a control message channel
	type controlMsg struct {
		Type    string `json:"type"`
		Message string `json:"message,omitempty"`
		Error   string `json:"error,omitempty"`
	}

	// Send ready message
	err := conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"ready"}`))
	if err != nil {
		return err
	}

	// Handle incoming connection requests
	for {
		msgType, message, err := conn.Read(context.Background())
		if err != nil {
			return err
		}

		if msgType != websocket.MessageText {
			continue
		}

		var msg controlMsg
		if err := json.Unmarshal(message, &msg); err != nil {
			q.logger.Error("parsing control message", zap.Error(err))
			continue
		}

		if msg.Type == "connect" {
			// Connect to the target
			targetConn, err := net.Dial("tcp", target)
			if err != nil {
				errorMsg := fmt.Sprintf(`{"type":"error", "error":"failed to connect to %s: %s"}`, target, err.Error())
				conn.Write(context.Background(), websocket.MessageText, []byte(errorMsg))
				continue
			}

			// Send success response
			conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"connected"}`))

			// Start forwarding data
			go q.forwardWebSocketToTCP(conn, targetConn)
		}
	}
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
	for {
		_, _, err := conn.Read(context.Background())
		if err != nil {
			break
		}
	}

	// Unregister the tunnel when the client disconnects
	q.tunnelsMu.Lock()
	delete(q.reverseTunnels, hostname)
	q.tunnelsMu.Unlock()

	q.logger.Info("unregistered reverse tunnel", zap.String("hostname", hostname))
	return nil
}

// handleSocks implements a SOCKS5 proxy (like SSH -D)
func (q *QuicSSHProxy) handleSocks(conn *websocket.Conn, r *http.Request) error {
	// Read the initial SOCKS handshake
	_, message, err := conn.Read(context.Background())
	if err != nil {
		return err
	}

	// Verify this is a SOCKS5 request
	if len(message) < 2 || message[0] != 0x05 {
		conn.Close(websocket.StatusCode(4000), "not a valid SOCKS5 request")
		return nil
	}

	// Reply with no authentication required
	err = conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x00})
	if err != nil {
		return err
	}

	// Read the connection request
	_, message, err = conn.Read(context.Background())
	if err != nil {
		return err
	}

	// Check for CONNECT command
	if len(message) < 4 || message[0] != 0x05 || message[1] != 0x01 {
		conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil
	}

	// Parse address type
	var target string
	switch message[3] {
	case 0x01: // IPv4
		if len(message) < 10 {
			conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return nil
		}
		ip := net.IPv4(message[4], message[5], message[6], message[7])
		port := int(message[8])<<8 | int(message[9])
		target = fmt.Sprintf("%s:%d", ip.String(), port)

	case 0x03: // Domain name
		if len(message) < 5 {
			conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return nil
		}
		domainLen := int(message[4])
		if len(message) < 5+domainLen+2 {
			conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return nil
		}
		domain := string(message[5 : 5+domainLen])
		port := int(message[5+domainLen])<<8 | int(message[5+domainLen+1])
		target = fmt.Sprintf("%s:%d", domain, port)

	case 0x04: // IPv6
		if len(message) < 22 {
			conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return nil
		}
		ip := net.IP(message[4:20])
		port := int(message[20])<<8 | int(message[21])
		target = fmt.Sprintf("[%s]:%d", ip.String(), port)

	default:
		conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil
	}

	// Check if the destination is allowed
	if !q.isDestinationAllowed(target) {
		conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil
	}

	// Connect to the target
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write(context.Background(), websocket.MessageBinary, []byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil
	}
	defer targetConn.Close()

	// Send success response
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	ipBytes := localAddr.IP.To4()
	if ipBytes == nil {
		ipBytes = localAddr.IP.To16()
		response := []byte{0x05, 0x00, 0x00, 0x04}
		response = append(response, ipBytes...)
		response = append(response, byte(localAddr.Port>>8), byte(localAddr.Port&0xff))
		conn.Write(context.Background(), websocket.MessageBinary, response)
	} else {
		response := []byte{0x05, 0x00, 0x00, 0x01, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], byte(localAddr.Port >> 8), byte(localAddr.Port & 0xff)}
		conn.Write(context.Background(), websocket.MessageBinary, response)
	}

	// Start forwarding data
	q.forwardWebSocketToTCP(conn, targetConn)
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
