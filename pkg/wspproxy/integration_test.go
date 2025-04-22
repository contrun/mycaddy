package wspproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/gorilla/websocket"
)

// Integration test for the WebSocket proxy
func TestWebSocketProxyIntegration(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start a WebSocket echo server
	echoServerPort := getFreePort()
	echoServerAddr := fmt.Sprintf("localhost:%d", echoServerPort)
	t.Logf("Starting WebSocket echo server on %s", echoServerAddr)

	// Create a context that can be used to shut down the echo server
	echoCtx, echoCancel := context.WithCancel(context.Background())
	defer echoCancel()

	// Start the echo server in a goroutine
	go func() {
		startEchoServer(echoCtx, echoServerAddr)
	}()

	// Allow the echo server to start
	time.Sleep(100 * time.Millisecond)

	// Configure and start Caddy with our WebSocket proxy
	caddyPort := getFreePort()
	caddyAddr := fmt.Sprintf("localhost:%d", caddyPort)
	t.Logf("Starting Caddy server on %s", caddyAddr)

	// Create a Caddyfile with our WebSocket proxy configuration
	// The order directive is critical - it must be placed in the global options block
	// to tell Caddy that wspproxy is an HTTP handler that should be ordered in the middleware chain
	caddyfileContent := fmt.Sprintf(`
	{
		admin off
		debug
		order wspproxy before respond
	}

	http://%s {
		# Path-based WebSocket proxy
		route /chat/* {
			wspproxy path_regex {
				upstream_template ws://%s/echo?room={value}
				path_regex /chat/([^/]+)
			}
		}

		# Static WebSocket proxy
		route /static/ws {
			wspproxy static {
				upstream_template ws://%s/echo
			}
		}

		# Query parameter-based WebSocket proxy
		route /ws {
			wspproxy query_param {
				upstream_template ws://%s/echo?room={value}
				query_param room
				default_upstream ws://%s/echo
			}
		}

		# Header-based WebSocket proxy
		route /api/ws {
			wspproxy header {
				upstream_template ws://%s/echo?room={value}
				header_name X-WS-Room
				default_upstream ws://%s/echo
			}
		}

		# Serve a simple response for all other requests
		respond "WebSocket Proxy Test Server"
	}
	`, caddyAddr, echoServerAddr, echoServerAddr, echoServerAddr, echoServerAddr, echoServerAddr, echoServerAddr)

	// Load and start Caddy with our configuration
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := startCaddy(ctx, caddyfileContent)
	if err != nil {
		t.Fatalf("Failed to start Caddy: %v", err)
	}
	// Ensure Caddy is stopped after the test
	defer caddy.Stop()

	// Allow Caddy to start
	time.Sleep(500 * time.Millisecond)

	// Test cases for different proxy methods
	testCases := []struct {
		name       string
		path       string
		headers    map[string]string
		roomValue  string // Expected room value
		wantStatus int
	}{
		{
			name:       "Path-based proxy",
			path:       "/chat/room123",
			headers:    nil,
			roomValue:  "room123",
			wantStatus: http.StatusSwitchingProtocols,
		},
		{
			name:       "Static proxy",
			path:       "/static/ws",
			headers:    nil,
			roomValue:  "",
			wantStatus: http.StatusSwitchingProtocols,
		},
		{
			name:       "Query parameter-based proxy",
			path:       "/ws?room=room456",
			headers:    nil,
			roomValue:  "room456",
			wantStatus: http.StatusSwitchingProtocols,
		},
		{
			name:       "Header-based proxy",
			path:       "/api/ws",
			headers:    map[string]string{"X-WS-Room": "room789"},
			roomValue:  "room789",
			wantStatus: http.StatusSwitchingProtocols,
		},
		{
			name:       "Default upstream fallback",
			path:       "/ws", // No room query parameter
			headers:    nil,
			roomValue:  "",
			wantStatus: http.StatusSwitchingProtocols,
		},
	}

	// Run tests for each case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a WebSocket client and connect to the proxy
			wsURL := url.URL{
				Scheme: "ws",
				Host:   caddyAddr,
				Path:   tc.path,
			}

			// Handle query parameters separately from the path
			if strings.Contains(tc.path, "?") {
				parts := strings.SplitN(tc.path, "?", 2)
				wsURL.Path = parts[0]
				wsURL.RawQuery = parts[1]
			}

			t.Logf("Connecting to WebSocket proxy at %s", wsURL.String())

			// Create custom header if needed
			header := http.Header{}
			if tc.headers != nil {
				for k, v := range tc.headers {
					header.Set(k, v)
				}
			}

			// Connect to the WebSocket server
			ws, resp, err := websocket.DefaultDialer.Dial(wsURL.String(), header)
			if err != nil {
				t.Fatalf("Failed to connect to WebSocket server: %v", err)
			}
			defer ws.Close()

			// Check response status
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("Unexpected status code: got %d, want %d", resp.StatusCode, tc.wantStatus)
			}

			// Send a test message
			testMessage := "Hello, WebSocket proxy!"
			if err := ws.WriteMessage(websocket.TextMessage, []byte(testMessage)); err != nil {
				t.Fatalf("Failed to send message: %v", err)
			}

			// Read the echo response with timeout
			ws.SetReadDeadline(time.Now().Add(5 * time.Second))
			messageType, message, err := ws.ReadMessage()
			if err != nil {
				t.Fatalf("Failed to read message: %v", err)
			}

			// Verify the response
			expectedPrefix := testMessage
			if tc.roomValue != "" {
				expectedPrefix += " (room: " + tc.roomValue + ")"
			}

			if messageType != websocket.TextMessage {
				t.Errorf("Unexpected message type: got %d, want %d", messageType, websocket.TextMessage)
			}

			messageStr := string(message)
			if !strings.HasPrefix(messageStr, expectedPrefix) {
				t.Errorf("Unexpected message content:\nGot:  %s\nWant: %s", messageStr, expectedPrefix)
			} else {
				t.Logf("Successfully received echo response: %s", messageStr)
			}

			// Close the connection
			ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		})
	}
}

// startEchoServer starts a WebSocket echo server for testing
func startEchoServer(ctx context.Context, addr string) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow connections from any origin for testing
		},
	}

	// Create a server with a context for shutdown
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/echo" {
				// Get room from query parameter if present
				room := r.URL.Query().Get("room")
				log.Printf("[Echo Server] New connection request, room: %s", room)

				// Upgrade the connection to WebSocket
				c, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					log.Printf("[Echo Server] Upgrade error: %v", err)
					return
				}
				defer c.Close()

				log.Printf("[Echo Server] Client connected: %s, room: %s", r.RemoteAddr, room)

				// Echo loop
				for {
					mt, message, err := c.ReadMessage()
					if err != nil {
						if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
							log.Printf("[Echo Server] Client disconnected normally: %s", r.RemoteAddr)
						} else {
							log.Printf("[Echo Server] Read error: %v", err)
						}
						break
					}
					log.Printf("[Echo Server] Received message from %s: %s", r.RemoteAddr, message)

					// Add room info to the echo response if specified
					var response []byte
					if room != "" {
						response = []byte(fmt.Sprintf("%s (room: %s)", message, room))
					} else {
						response = message
					}

					// Echo the message back
					if err := c.WriteMessage(mt, response); err != nil {
						log.Printf("[Echo Server] Write error: %v", err)
						break
					}
				}
			} else {
				// Root handler
				w.Write([]byte("WebSocket Echo Server - Connect to /echo"))
			}
		}),
	}

	// Handle server shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	// Start the server
	log.Printf("[Echo Server] Starting on %s", addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("[Echo Server] Server error: %v", err)
	}
}

// startCaddy initializes and starts a Caddy instance with the given Caddyfile content
func startCaddy(ctx context.Context, caddyfileContent string) error {
	// First, stop any existing Caddy instance
	err := caddy.Stop()
	if err != nil {
		return fmt.Errorf("stopping caddy: %v", err)
	}

	// Parse the Caddyfile
	adapter := caddyfile.Adapter{
		ServerType: httpcaddyfile.ServerType{},
	}

	config, warn, err := adapter.Adapt([]byte(caddyfileContent), nil)
	if err != nil {
		return fmt.Errorf("adapting config: %v", err)
	}
	if warn != nil {
		log.Printf("Warning: %v", warn)
	}

	// Load the config
	err = caddy.Load(config, true)
	if err != nil {
		return fmt.Errorf("loading config: %v", err)
	}

	return nil
}

// getFreePort returns a free port number
func getFreePort() int {
	// This is a simple way to get a free port
	// We listen on a random port (port 0) and then close it
	// The OS will assign a free port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("Failed to find free port: %v", err)
	}
	defer listener.Close()

	// Extract the port from the listener's address
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		log.Fatalf("Failed to extract port: %v", err)
	}

	// Convert port to integer
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Failed to convert port to integer: %v", err)
	}

	return port
}
