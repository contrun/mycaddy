// Package tests provides integration tests for quicssh-proxy
package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

const (
	caddyConfig = `
	{
		"apps": {
			"http": {
				"servers": {
					"quicssh": {
						"listen": [":9080"],
						"routes": [
							{
								"handle": [
									{
										"handler": "quicssh_proxy",
										"listen_addr": ":9443",
										"allow_reverse_tunnel": true,
										"allow_socks5": true
									}
								]
							}
						]
					}
				}
			}
		}
	}
	`
	testTimeout    = 30 * time.Second
	quicTestAddr   = "localhost:9443"
	httpTestAddr   = "localhost:9080"
	mockSSHPort    = 2222
	mockSSHAddr    = "localhost:2222"
	httpServerAddr = "localhost:8000"
)

var (
	caddyPath      string
	mockSSHServer  *mockSSH
	mockHTTPServer *http.Server
	testRootDir    string
)

// setupTestEnv prepares the test environment
func setupTestEnv(t *testing.T) (func(), error) {
	t.Helper()

	// Create a temporary directory for test files
	var err error
	testRootDir, err = os.MkdirTemp("", "quicssh-test-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Start a mock SSH server
	mockSSHServer, err = startMockSSHServer(mockSSHPort)
	if err != nil {
		os.RemoveAll(testRootDir)
		return nil, fmt.Errorf("failed to start mock SSH server: %w", err)
	}

	// Start a mock HTTP server for SOCKS tests
	mockHTTPServer = startMockHTTPServer()

	// Find the Caddy executable
	caddyPath, err = exec.LookPath("caddy")
	if err != nil {
		// Try common locations relative to the test directory
		potentialPaths := []string{
			filepath.Join(testRootDir, "..", "..", "..", "mycaddy"),
			filepath.Join(testRootDir, "..", "..", "..", "caddy"),
		}
		for _, path := range potentialPaths {
			absPath, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			if _, err := os.Stat(absPath); err == nil {
				caddyPath = absPath
				break
			}
		}
	}

	if caddyPath == "" {
		// If we can't find Caddy, build it
		caddyPath = filepath.Join(testRootDir, "caddy")
		cmd := exec.Command("go", "build", "-o", caddyPath, "../../../cmd/caddy")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to build caddy: %w", err)
		}
	}

	// Return a cleanup function
	return cleanup, nil
}

// cleanup cleans up the test environment
func cleanup() {
	// Stop the mock HTTP server
	if mockHTTPServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		mockHTTPServer.Shutdown(ctx)
	}

	// Stop the mock SSH server
	if mockSSHServer != nil {
		mockSSHServer.stop()
	}

	// Remove the test directory
	if testRootDir != "" {
		os.RemoveAll(testRootDir)
	}
}

// startMockHTTPServer starts a simple HTTP server for testing
func startMockHTTPServer() *http.Server {
	server := &http.Server{
		Addr: httpServerAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("QUICSSH-PROXY-TEST-RESPONSE"))
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	// Wait for server to start
	for i := 0; i < 10; i++ {
		if canConnectTo(httpServerAddr) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return server
}

// mockSSH is a simple SSH server for testing
type mockSSH struct {
	config      *ssh.ServerConfig
	listener    net.Listener
	doneCh      chan struct{}
	connections []net.Conn
	mu          sync.Mutex
}

// startMockSSHServer starts a mock SSH server for testing
func startMockSSHServer(port int) (*mockSSH, error) {
	// Generate server key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH server key: %w", err)
	}

	private, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}

	// Create server config
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(private)

	// Start listener
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	server := &mockSSH{
		config:      config,
		listener:    listener,
		doneCh:      make(chan struct{}),
		connections: make([]net.Conn, 0),
	}

	go server.serve()

	return server, nil
}

// serve handles SSH connections
func (s *mockSSH) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.doneCh:
				return // Server is shutting down
			default:
				fmt.Printf("SSH accept error: %v\n", err)
				continue
			}
		}

		s.mu.Lock()
		s.connections = append(s.connections, conn)
		s.mu.Unlock()

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SSH connection
func (s *mockSSH) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		// Just accepting the SSH banner is enough for our tests
		return
	}
	defer sshConn.Close()

	// Service the incoming Channel and Request channels
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("Could not accept channel: %v\n", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				// Just echo the payload for testing
				if req.WantReply {
					req.Reply(true, nil)
				}
			}
		}(requests)

		go func() {
			defer channel.Close()
			io.Copy(channel, channel) // Echo anything received
		}()
	}
}

// stop shuts down the SSH server
func (s *mockSSH) stop() {
	close(s.doneCh)
	s.listener.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, conn := range s.connections {
		conn.Close()
	}
}

// canConnectTo checks if we can establish a TCP connection to the given address
func canConnectTo(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// startCaddy starts the Caddy server with our test configuration
func startCaddy(t *testing.T) (*exec.Cmd, error) {
	t.Helper()

	// Create a temporary config file
	configFile, err := os.CreateTemp(testRootDir, "caddy-config-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp config file: %w", err)
	}
	defer configFile.Close()

	_, err = configFile.WriteString(caddyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}

	// Start Caddy with the config
	cmd := exec.Command(caddyPath, "run", "--config", configFile.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start caddy: %w", err)
	}

	// Wait for Caddy to start and for listeners to be ready
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if canConnectTo(httpTestAddr) {
			return cmd, nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	// If we got here, Caddy didn't start properly
	cmd.Process.Kill()
	return nil, fmt.Errorf("caddy didn't start within timeout")
}

// stopCaddy stops the Caddy server
func stopCaddy(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	}
}

// TestDirectForwarding tests the direct forwarding functionality (like SSH -L)
func TestDirectForwarding(t *testing.T) {
	cleanup, err := setupTestEnv(t)
	if err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	defer cleanup()

	// Start Caddy with our config
	caddy, err := startCaddy(t)
	if err != nil {
		t.Fatalf("Failed to start Caddy: %v", err)
	}
	defer stopCaddy(caddy)

	// Test using a QUIC connection with SNI for direct forwarding
	t.Run("QUIC-Direct-Forwarding", func(t *testing.T) {
		// Create a QUIC connection to the proxy with SNI set to the SSH server address
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"quicssh"},
			ServerName:         mockSSHAddr, // Use SNI to specify target
		}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		session, err := quic.DialAddr(ctx, quicTestAddr, tlsConf, nil)
		if err != nil {
			t.Fatalf("Failed to establish QUIC connection: %v", err)
		}
		defer session.CloseWithError(0, "test complete")

		// Open a stream
		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("Failed to open QUIC stream: %v", err)
		}
		defer stream.Close()

		// Send SSH protocol identifier to verify we're connected to an SSH server
		_, err = stream.Write([]byte("SSH-2.0-QuicSSHTest\r\n"))
		if err != nil {
			t.Fatalf("Failed to write to QUIC stream: %v", err)
		}

		// Read response from SSH server
		buffer := make([]byte, 1024)
		n, err := stream.Read(buffer)
		if err != nil {
			t.Fatalf("Failed to read from QUIC stream: %v", err)
		}

		response := string(buffer[:n])
		if !strings.HasPrefix(response, "SSH-") {
			t.Errorf("Response doesn't start with SSH protocol identifier: %s", response)
		}
	})

	// Test using WebSocket for direct forwarding
	t.Run("WebSocket-Direct-Forwarding", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Connect to the WebSocket endpoint
		url := fmt.Sprintf("ws://%s/quicssh/forward?target=%s", httpTestAddr, mockSSHAddr)
		conn, _, err := websocket.Dial(ctx, url, nil)
		if err != nil {
			t.Fatalf("Failed to establish WebSocket connection: %v", err)
		}
		defer conn.Close(websocket.StatusNormalClosure, "test complete")

		// Send SSH protocol identifier
		err = conn.Write(ctx, websocket.MessageBinary, []byte("SSH-2.0-QuicSSHTest\r\n"))
		if err != nil {
			t.Fatalf("Failed to send SSH protocol identifier: %v", err)
		}

		// Read response from SSH server
		_, message, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("Failed to read SSH server response: %v", err)
		}

		response := string(message)
		if !strings.HasPrefix(response, "SSH-") {
			t.Errorf("Response doesn't start with SSH protocol identifier: %s", response)
		}
	})
}

// TestReverseTunneling tests the reverse tunneling functionality (like SSH -R)
func TestReverseTunneling(t *testing.T) {
	cleanup, err := setupTestEnv(t)
	if err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	defer cleanup()

	// Start Caddy with our config
	caddy, err := startCaddy(t)
	if err != nil {
		t.Fatalf("Failed to start Caddy: %v", err)
	}
	defer stopCaddy(caddy)

	// Start a simple echo server to act as the target
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer listener.Close()

	echoServerAddr := listener.Addr().String()

	// Handle connections in a goroutine
	echoConnCh := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			echoConnCh <- conn
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						if err != io.EOF {
							fmt.Printf("Echo server read error: %v\n", err)
						}
						return
					}
					_, err = c.Write(buf[:n])
					if err != nil {
						fmt.Printf("Echo server write error: %v\n", err)
						return
					}
				}
			}(conn)
		}
	}()

	// Test using WebSocket for reverse tunneling
	t.Run("WebSocket-Reverse-Tunneling", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Hostname for the tunnel
		hostname := "test.tunnel.local"

		// Register the reverse tunnel
		url := fmt.Sprintf("ws://%s/quicssh/reverse?hostname=%s&target=%s",
			httpTestAddr, hostname, echoServerAddr)
		wsReg, _, err := websocket.Dial(ctx, url, nil)
		if err != nil {
			t.Fatalf("Failed to establish WebSocket connection for registration: %v", err)
		}
		defer wsReg.Close(websocket.StatusNormalClosure, "test complete")

		// Now connect to the tunnel via QUIC
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"quicssh"},
			ServerName:         hostname, // Use the registered hostname
		}

		session, err := quic.DialAddr(ctx, quicTestAddr, tlsConf, nil)
		if err != nil {
			t.Fatalf("Failed to establish QUIC connection to tunnel: %v", err)
		}
		defer session.CloseWithError(0, "test complete")

		// Open a stream
		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("Failed to open QUIC stream: %v", err)
		}
		defer stream.Close()

		// Send data through the tunnel
		testMessage := "Hello QUIC Tunnel!"
		_, err = stream.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("Failed to write to QUIC stream: %v", err)
		}

		// Read response from echo server
		buffer := make([]byte, 1024)
		n, err := stream.Read(buffer)
		if err != nil {
			t.Fatalf("Failed to read from QUIC stream: %v", err)
		}

		response := string(buffer[:n])
		if response != testMessage {
			t.Errorf("Echo response doesn't match sent message. Got %q, expected %q", response, testMessage)
		}
	})
}

// TestSOCKSProxy tests the SOCKS5 proxy functionality (like SSH -D)
func TestSOCKSProxy(t *testing.T) {
	cleanup, err := setupTestEnv(t)
	if err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	defer cleanup()

	// Start Caddy with our config
	caddy, err := startCaddy(t)
	if err != nil {
		t.Fatalf("Failed to start Caddy: %v", err)
	}
	defer stopCaddy(caddy)

	// Test using WebSocket for SOCKS5 proxy
	t.Run("WebSocket-SOCKS5-Proxy", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Connect to the WebSocket SOCKS endpoint
		url := fmt.Sprintf("ws://%s/quicssh/socks", httpTestAddr)
		conn, _, err := websocket.Dial(ctx, url, nil)
		if err != nil {
			t.Fatalf("Failed to establish WebSocket connection: %v", err)
		}
		defer conn.Close(websocket.StatusNormalClosure, "test complete")

		// SOCKS5 handshake - offer no authentication
		err = conn.Write(ctx, websocket.MessageBinary, []byte{
			0x05, // SOCKS version
			0x01, // Number of authentication methods
			0x00, // No authentication
		})
		if err != nil {
			t.Fatalf("Failed to send SOCKS5 handshake: %v", err)
		}

		// Read server choice
		_, message, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("Failed to read SOCKS5 handshake response: %v", err)
		}
		if len(message) != 2 {
			t.Fatalf("Invalid SOCKS5 handshake response length: %d", len(message))
		}
		if message[0] != 0x05 {
			t.Errorf("Wrong SOCKS version in response: 0x%02x", message[0])
		}
		if message[1] != 0x00 {
			t.Errorf("Server did not accept no authentication: 0x%02x", message[1])
		}

		// Parse target address (httpServerAddr)
		host, portStr, err := net.SplitHostPort(httpServerAddr)
		if err != nil {
			t.Fatalf("Failed to parse HTTP server address: %v", err)
		}

		var port int
		_, err = fmt.Sscanf(portStr, "%d", &port)
		if err != nil {
			t.Fatalf("Failed to parse port: %v", err)
		}

		// SOCKS5 connect command with domain name
		domainLen := len(host)
		connectCmd := []byte{
			0x05,            // SOCKS version
			0x01,            // CONNECT command
			0x00,            // Reserved
			0x03,            // Domain name address type
			byte(domainLen), // Domain name length
		}
		connectCmd = append(connectCmd, []byte(host)...)
		connectCmd = append(connectCmd, byte(port>>8), byte(port&0xff)) // Port in network byte order

		err = conn.Write(ctx, websocket.MessageBinary, connectCmd)
		if err != nil {
			t.Fatalf("Failed to send SOCKS5 connect command: %v", err)
		}

		// Read connect response
		_, message, err = conn.Read(ctx)
		if err != nil {
			t.Fatalf("Failed to read SOCKS5 connect response: %v", err)
		}
		if len(message) < 7 {
			t.Fatalf("Invalid SOCKS5 connect response length: %d", len(message))
		}
		if message[0] != 0x05 {
			t.Errorf("Wrong SOCKS version in response: 0x%02x", message[0])
		}
		if message[1] != 0x00 {
			t.Errorf("SOCKS connection failed with error code: 0x%02x", message[1])
		}

		// Send HTTP request through the SOCKS proxy
		httpReq := "GET / HTTP/1.1\r\nHost: " + httpServerAddr + "\r\nConnection: close\r\n\r\n"
		err = conn.Write(ctx, websocket.MessageBinary, []byte(httpReq))
		if err != nil {
			t.Fatalf("Failed to send HTTP request through SOCKS proxy: %v", err)
		}

		// Read HTTP response
		var responseBuilder strings.Builder
		var gotResponse bool

		// We may need multiple reads to get the full response
		for i := 0; i < 10; i++ {
			_, message, err = conn.Read(ctx)
			if err != nil {
				break
			}
			responseBuilder.Write(message)

			// Check if we got the test marker
			if strings.Contains(responseBuilder.String(), "QUICSSH-PROXY-TEST-RESPONSE") {
				gotResponse = true
				break
			}
		}

		if !gotResponse {
			t.Errorf("Did not receive expected HTTP response through SOCKS proxy. Got: %s", responseBuilder.String())
		}
	})
}
