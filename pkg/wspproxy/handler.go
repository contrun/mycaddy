// Package wspproxy implements a WebSocket proxy handler for Caddy
package wspproxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("wspproxy", ParseCaddyfile)
}

// Handler implements a WebSocket proxy handler that dynamically determines
// upstream WebSocket servers based on configured rules
type Handler struct {
	// The method used to determine the upstream WebSocket server
	Method string `json:"method,omitempty"`

	// UpstreamTemplate is the template for constructing the upstream URL
	UpstreamTemplate string `json:"upstream_template,omitempty"`

	// PathRegex is a regex pattern to extract values from the request path
	PathRegex string `json:"path_regex,omitempty"`

	// HeaderName is the name of the header containing the upstream information
	HeaderName string `json:"header_name,omitempty"`

	// QueryParam is the name of the query parameter containing upstream information
	QueryParam string `json:"query_param,omitempty"`

	// DefaultUpstream is the default upstream if dynamic resolution fails
	DefaultUpstream string `json:"default_upstream,omitempty"`

	// Compiled regex pattern
	pathRegexPattern *regexp.Regexp

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wspproxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	// Compile the regex pattern if provided
	if h.PathRegex != "" {
		var err error
		h.pathRegexPattern, err = regexp.Compile(h.PathRegex)
		if err != nil {
			return fmt.Errorf("invalid path regex pattern: %w", err)
		}
	}

	return nil
}

// Validate ensures the handler's configuration is valid.
func (h *Handler) Validate() error {
	if h.Method == "" {
		return errors.New("method must be specified")
	}

	if h.UpstreamTemplate == "" {
		return errors.New("upstream_template must be specified")
	}

	switch h.Method {
	case "path_regex":
		if h.PathRegex == "" {
			return errors.New("path_regex must be specified when method is path_regex")
		}
	case "header":
		if h.HeaderName == "" {
			return errors.New("header_name must be specified when method is header")
		}
	case "query_param":
		if h.QueryParam == "" {
			return errors.New("query_param must be specified when method is query_param")
		}
	case "static":
		// Static method uses the template directly without substitution
	default:
		return fmt.Errorf("unknown method: %s", h.Method)
	}

	return nil
}

// ServeHTTP handles the HTTP request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Only handle WebSocket upgrade requests
	if !isWebSocketUpgrade(r) {
		return next.ServeHTTP(w, r)
	}

	// Determine the upstream WebSocket server
	upstreamURL, err := h.determineUpstreamURL(r)
	if err != nil {
		h.logger.Error("failed to determine upstream URL", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	h.logger.Debug("proxying websocket connection",
		zap.String("upstream", upstreamURL.String()),
		zap.String("path", r.URL.Path))

	// Proxy the WebSocket connection
	return h.proxyWebSocket(w, r, upstreamURL)
}

// determineUpstreamURL determines the upstream WebSocket server URL based on the request
func (h *Handler) determineUpstreamURL(r *http.Request) (*url.URL, error) {
	var value string
	var err error

	switch h.Method {
	case "path_regex":
		value, err = h.extractFromPath(r.URL.Path)
		if err != nil {
			if h.DefaultUpstream != "" {
				return url.Parse(h.DefaultUpstream)
			}
			return nil, err
		}
	case "header":
		value = r.Header.Get(h.HeaderName)
		if value == "" {
			if h.DefaultUpstream != "" {
				return url.Parse(h.DefaultUpstream)
			}
			return nil, fmt.Errorf("header %s not found or empty", h.HeaderName)
		}
	case "query_param":
		value = r.URL.Query().Get(h.QueryParam)
		if value == "" {
			if h.DefaultUpstream != "" {
				return url.Parse(h.DefaultUpstream)
			}
			return nil, fmt.Errorf("query parameter %s not found or empty", h.QueryParam)
		}
	case "static":
		return url.Parse(h.UpstreamTemplate)
	default:
		return nil, fmt.Errorf("unknown method: %s", h.Method)
	}

	// Replace the placeholder in the template with the extracted value
	upstreamStr := strings.Replace(h.UpstreamTemplate, "{value}", value, -1)

	// Add scheme if not provided
	if !strings.HasPrefix(upstreamStr, "ws://") && !strings.HasPrefix(upstreamStr, "wss://") {
		if r.TLS != nil {
			upstreamStr = "wss://" + upstreamStr
		} else {
			upstreamStr = "ws://" + upstreamStr
		}
	}

	return url.Parse(upstreamStr)
}

// extractFromPath extracts values from the request path using the configured regex
func (h *Handler) extractFromPath(path string) (string, error) {
	if h.pathRegexPattern == nil {
		return "", errors.New("path regex pattern not compiled")
	}

	matches := h.pathRegexPattern.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", errors.New("no match found in path")
	}

	// Use the first capturing group as the extracted value
	return matches[1], nil
}

// proxyWebSocket proxies the WebSocket connection
func (h *Handler) proxyWebSocket(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL) error {
	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	// Determine if we need to use TLS
	useTLS := upstreamURL.Scheme == "wss" || upstreamURL.Scheme == "https"

	// Convert ws/wss to http/https for the upstream request
	requestURL := *upstreamURL
	switch requestURL.Scheme {
	case "ws":
		requestURL.Scheme = "http"
	case "wss":
		requestURL.Scheme = "https"
	}

	// Copy the headers from the client request
	header := make(http.Header)
	for k, vv := range r.Header {
		for _, v := range vv {
			header.Add(k, v)
		}
	}

	// Update the Host header to match the upstream URL
	header.Set("Host", upstreamURL.Host)

	// Add X-Forwarded-* headers
	header.Set("X-Forwarded-For", r.RemoteAddr)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		header.Set("X-Forwarded-Proto", proto)
	} else if r.TLS != nil {
		header.Set("X-Forwarded-Proto", "https")
	} else {
		header.Set("X-Forwarded-Proto", "http")
	}

	h.logger.Debug("connecting to upstream websocket",
		zap.String("url", upstreamURL.String()),
		zap.Any("headers", header))

	// Connect to the upstream server
	var conn net.Conn
	var err error

	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", upstreamURL.Host, &tls.Config{
			InsecureSkipVerify: false, // Set to true if you need to skip certificate validation
		})
	} else {
		conn, err = dialer.Dial("tcp", upstreamURL.Host)
	}

	if err != nil {
		h.logger.Error("failed to connect to upstream", zap.Error(err))
		return fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	// Construct the HTTP request for the WebSocket upgrade
	path := upstreamURL.Path
	if upstreamURL.RawQuery != "" {
		path += "?" + upstreamURL.RawQuery
	}

	// Create the upgrade request
	upgradeReq := fmt.Sprintf("GET %s HTTP/1.1\r\n", path)

	// Add headers
	for k, vv := range header {
		for _, v := range vv {
			upgradeReq += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	upgradeReq += "\r\n"

	// Write the upgrade request to the upstream connection
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		h.logger.Error("failed to write upgrade request", zap.Error(err))
		return fmt.Errorf("failed to write upgrade request: %w", err)
	}

	// Read the response from the upstream server
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		h.logger.Error("failed to read response", zap.Error(err))
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check if the WebSocket upgrade was successful
	if resp.StatusCode != http.StatusSwitchingProtocols {
		h.logger.Error("websocket upgrade failed",
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status))

		// Copy headers and status code to the response
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// Copy the response body
		io.Copy(w, resp.Body)
		resp.Body.Close()

		return nil
	}

	h.logger.Debug("websocket upgrade successful, hijacking connection")

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("webserver doesn't support hijacking")
	}
	clientConn, clientBufRW, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack client connection: %w", err)
	}
	defer clientConn.Close()

	// Write the response status line
	if _, err := clientBufRW.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status)); err != nil {
		return fmt.Errorf("failed to write status line: %w", err)
	}

	// Write response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			if _, err := clientBufRW.WriteString(fmt.Sprintf("%s: %s\r\n", k, v)); err != nil {
				return fmt.Errorf("failed to write header: %w", err)
			}
		}
	}

	// End headers
	if _, err := clientBufRW.WriteString("\r\n"); err != nil {
		return fmt.Errorf("failed to write header terminator: %w", err)
	}
	if err := clientBufRW.Flush(); err != nil {
		return fmt.Errorf("failed to flush headers: %w", err)
	}

	h.logger.Debug("starting bidirectional proxy between client and upstream")

	// Set up bidirectional copy
	errCh := make(chan error, 2)

	// Copy from client to upstream
	go func() {
		_, err := io.Copy(conn, clientConn)
		errCh <- err
	}()

	// Copy from upstream to client
	go func() {
		_, err := io.Copy(clientConn, conn)
		errCh <- err
	}()

	// Wait for one of the connections to close
	err = <-errCh
	if err != nil && !isConnectionClosed(err) {
		h.logger.Error("websocket proxy error", zap.Error(err))
	} else {
		h.logger.Debug("websocket connection closed", zap.Error(err))
	}

	return nil
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// hijackConnection hijacks the HTTP connection
func hijackConnection(w http.ResponseWriter) (*hijackedConn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection doesn't support hijacking")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	return &hijackedConn{
		Conn:           conn,
		Reader:         bufrw.Reader,
		Writer:         bufrw.Writer,
		ResponseHeader: make(http.Header),
	}, nil
}

// hijackedConn represents a hijacked HTTP connection
type hijackedConn struct {
	net.Conn
	Reader         *bufio.Reader
	Writer         *bufio.Writer
	ResponseHeader http.Header
}

// Write writes data to the connection
func (hc *hijackedConn) Write(b []byte) (int, error) {
	return hc.Writer.Write(b)
}

// Read reads data from the connection
func (hc *hijackedConn) Read(b []byte) (int, error) {
	return hc.Reader.Read(b)
}

// Close closes the connection
func (hc *hijackedConn) Close() error {
	return hc.Conn.Close()
}

// connectWebSocket connects to an upstream WebSocket server
func connectWebSocket(req *http.Request) (net.Conn, *http.Response, error) {
	// Convert ws:// and wss:// to http:// and https://
	u := *req.URL
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}

	// Connect to the upstream server
	var conn net.Conn
	var err error

	dialer := &net.Dialer{}
	if u.Scheme == "https" {
		conn, err = tls.Dial("tcp", u.Host, &tls.Config{})
	} else {
		conn, err = dialer.Dial("tcp", u.Host)
	}
	if err != nil {
		return nil, nil, err
	}

	// Write the request to the connection
	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Read the response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Check if the upgrade was successful
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, resp, fmt.Errorf("websocket upgrade failed: %d", resp.StatusCode)
	}

	return conn, resp, nil
}

// isConnectionClosed checks if the error is due to a closed connection
func isConnectionClosed(err error) bool {
	return err == io.EOF ||
		errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(err.Error(), "use of closed network connection")
}

// UnmarshalCaddyfile unmarshal Caddyfile tokens
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			h.Method = d.Val()
		} else {
			return d.ArgErr()
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "upstream_template":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.UpstreamTemplate = d.Val()

			case "path_regex":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.PathRegex = d.Val()

			case "header_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.HeaderName = d.Val()

			case "query_param":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.QueryParam = d.Val()

			case "default_upstream":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.DefaultUpstream = d.Val()

			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}

	return nil
}

// ParseCaddyfile parses the wspproxy directive from Caddyfile
func ParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
