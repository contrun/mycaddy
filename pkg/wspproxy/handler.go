// Package wspproxy implements a multi-protocol proxy handler for Caddy
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
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("wspproxy", ParseCaddyfile)
}

// A ParameterSource defines where and how to extract a parameter
type ParameterSource struct {
	// Type of source (path_regex, header, query_param, static)
	Type string `json:"type,omitempty"`

	// Value for static parameters or pattern/name for dynamic parameters
	Value string `json:"value,omitempty"`

	// RegexPattern is the compiled regex for path_regex sources
	RegexPattern *regexp.Regexp `json:"-"`

	// Default value if parameter cannot be extracted
	Default string `json:"default,omitempty"`
}

// TLSConfig holds configuration for upstream TLS connections
type TLSConfig struct {
	// Whether to enable TLS for upstream connections
	Enabled bool `json:"enabled,omitempty"`

	// Whether to skip certificate verification
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// Optional CA certificate for verification
	CAFile string `json:"ca_file,omitempty"`

	// Optional client certificate
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// Server name for SNI
	ServerName string `json:"server_name,omitempty"`
}

// UpstreamProxyConfig holds configuration for upstream proxies
type UpstreamProxyConfig struct {
	// Type of proxy (none, http, socks5)
	Type string `json:"type,omitempty"`

	// URL of the proxy
	URL string `json:"url,omitempty"`

	// Username for proxy authentication
	Username string `json:"username,omitempty"`

	// Password for proxy authentication
	Password string `json:"password,omitempty"`
}

// Handler implements a multi-protocol proxy handler that dynamically determines
// upstream servers based on configured rules
type Handler struct {
	// Parameters to extract from the request
	Parameters map[string]ParameterSource `json:"parameters,omitempty"`

	// Protocol to use (ws, tcp, udp, quic)
	// Can be static or based on a parameter
	Protocol struct {
		// Static protocol or parameter name
		Value string `json:"value,omitempty"`

		// Whether Value is a static protocol or parameter name
		IsParameter bool `json:"is_parameter,omitempty"`

		// Default protocol if parameter is not found
		Default string `json:"default,omitempty"`
	} `json:"protocol,omitempty"`

	// UpstreamTemplate is the template for constructing the upstream URL/address
	// Can contain {parameter_name} placeholders
	UpstreamTemplate string `json:"upstream_template,omitempty"`

	// TLS configuration for upstream connections
	TLS TLSConfig `json:"tls,omitempty"`

	// Upstream proxy configuration
	UpstreamProxy UpstreamProxyConfig `json:"upstream_proxy,omitempty"`

	// Request headers to forward (for WebSocket)
	ForwardHeaders []string `json:"forward_headers,omitempty"`

	// Headers to add to the upstream request (for WebSocket)
	AddHeaders map[string]string `json:"add_headers,omitempty"`

	// The dial timeout for upstream connections
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// Logger
	logger *zap.Logger

	// Legacy support for backward compatibility with existing configurations
	// These fields should be considered deprecated but will be maintained for compatibility

	// Method is the method to determine the upstream server (deprecated, use Parameters instead)
	Method string `json:"method,omitempty"`

	// PathRegex is the regex pattern to extract value from path (deprecated)
	PathRegex string `json:"path_regex,omitempty"`

	// HeaderName is the header name to extract value from (deprecated)
	HeaderName string `json:"header_name,omitempty"`

	// QueryParam is the query parameter to extract value from (deprecated)
	QueryParam string `json:"query_param,omitempty"`

	// DefaultUpstream is the default upstream URL if value cannot be extracted (deprecated)
	DefaultUpstream string `json:"default_upstream,omitempty"`

	// Compiled regex pattern for path_regex method (deprecated)
	pathRegexPattern *regexp.Regexp
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

	// Initialize maps if they're nil
	if h.Parameters == nil {
		h.Parameters = make(map[string]ParameterSource)
	}

	if h.AddHeaders == nil {
		h.AddHeaders = make(map[string]string)
	}

	// Set default dial timeout if not specified
	if h.DialTimeout == 0 {
		h.DialTimeout = caddy.Duration(10 * time.Second)
	}

	// Compile regex patterns for path_regex parameter sources
	for name, param := range h.Parameters {
		if param.Type == "path_regex" && param.Value != "" {
			var err error
			pattern, err := regexp.Compile(param.Value)
			if err != nil {
				return fmt.Errorf("invalid regex pattern for parameter %s: %w", name, err)
			}
			param.RegexPattern = pattern
			h.Parameters[name] = param
		}
	}

	return nil
}

// Validate ensures the handler's configuration is valid.
func (h *Handler) Validate() error {
	// Verify we have at least one parameter or the old-style configuration
	if len(h.Parameters) == 0 && h.Method == "" {
		return errors.New("at least one parameter or legacy method must be defined")
	}

	// Verify upstream template is specified
	if h.UpstreamTemplate == "" {
		return errors.New("upstream_template must be specified")
	}

	// If using legacy configuration, validate accordingly
	if h.Method != "" {
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

	// Validate parameters
	for name, param := range h.Parameters {
		if param.Type == "" {
			return fmt.Errorf("parameter %s has no type specified", name)
		}

		switch param.Type {
		case "path_regex":
			if param.Value == "" {
				return fmt.Errorf("path_regex parameter %s must have a regex pattern", name)
			}
		case "header":
			if param.Value == "" {
				return fmt.Errorf("header parameter %s must have a header name", name)
			}
		case "query_param":
			if param.Value == "" {
				return fmt.Errorf("query_param parameter %s must have a query parameter name", name)
			}
		case "static":
			// Value is optional for static parameters
		default:
			return fmt.Errorf("unknown parameter type for %s: %s", name, param.Type)
		}
	}

	// Validate protocol configuration
	if h.Protocol.Value == "" {
		// Default to WebSocket if not specified
		h.Protocol.Value = "ws"
		h.Protocol.IsParameter = false
	} else if h.Protocol.IsParameter {
		// If protocol is a parameter, make sure it exists
		if _, exists := h.Parameters[h.Protocol.Value]; !exists {
			return fmt.Errorf("protocol parameter %s not defined", h.Protocol.Value)
		}
	} else {
		// If protocol is static, validate it
		switch h.Protocol.Value {
		case "ws", "tcp", "udp", "quic":
			// Valid protocols
		default:
			return fmt.Errorf("unknown protocol: %s", h.Protocol.Value)
		}
	}

	// Validate upstream proxy configuration
	if h.UpstreamProxy.Type != "" && h.UpstreamProxy.Type != "none" && h.UpstreamProxy.Type != "http" && h.UpstreamProxy.Type != "socks5" {
		return fmt.Errorf("unknown upstream proxy type: %s", h.UpstreamProxy.Type)
	}

	if h.UpstreamProxy.Type != "" && h.UpstreamProxy.Type != "none" && h.UpstreamProxy.URL == "" {
		return errors.New("upstream_proxy_url must be specified when using an upstream proxy")
	}

	return nil
}

// ServeHTTP handles the HTTP request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract all parameters from the request
	params, err := h.extractParameters(r)
	if err != nil {
		h.logger.Error("failed to extract parameters", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	// Determine the protocol to use
	protocol, err := h.determineProtocol(params)
	if err != nil {
		h.logger.Error("failed to determine protocol", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	// Build the upstream address/URL using the parameters
	upstreamAddress, err := h.buildUpstreamAddress(params)
	if err != nil {
		h.logger.Error("failed to build upstream address", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	h.logger.Debug("proxying connection",
		zap.String("protocol", protocol),
		zap.String("upstream", upstreamAddress),
		zap.String("path", r.URL.Path))

	// Handle the connection based on the protocol
	switch protocol {
	case "ws":
		// Handle WebSocket connections
		if !isWebSocketUpgrade(r) {
			return next.ServeHTTP(w, r)
		}
		upstreamURL, err := url.Parse(upstreamAddress)
		if err != nil {
			return caddyhttp.Error(http.StatusBadGateway, err)
		}
		return h.proxyWebSocket(w, r, upstreamURL, params)
	case "tcp":
		// Handle TCP connections
		return h.proxyTCP(w, r, upstreamAddress, params)
	case "udp":
		// Handle UDP connections
		return h.proxyUDP(w, r, upstreamAddress, params)
	case "quic":
		// Handle QUIC connections
		return h.proxyQUIC(w, r, upstreamAddress, params)
	default:
		h.logger.Error("unsupported protocol", zap.String("protocol", protocol))
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("unsupported protocol: %s", protocol))
	}
}

// extractParameters extracts all parameters from the request according to configuration
func (h *Handler) extractParameters(r *http.Request) (map[string]string, error) {
	// If using legacy configuration, extract the single parameter
	if h.Method != "" {
		return h.extractLegacyParameter(r)
	}

	// Extract all parameters
	params := make(map[string]string)
	for name, paramSource := range h.Parameters {
		value, err := h.extractParameter(r, paramSource)
		if err != nil {
			if paramSource.Default != "" {
				h.logger.Debug("using default value for parameter",
					zap.String("parameter", name),
					zap.String("default", paramSource.Default))
				params[name] = paramSource.Default
			} else {
				return nil, fmt.Errorf("failed to extract parameter %s: %w", name, err)
			}
		} else {
			params[name] = value
		}
	}

	return params, nil
}

// extractLegacyParameter extracts a parameter using the legacy configuration
func (h *Handler) extractLegacyParameter(r *http.Request) (map[string]string, error) {
	params := make(map[string]string)
	var value string
	var err error

	switch h.Method {
	case "path_regex":
		value, err = h.extractFromPath(r.URL.Path)
		if err != nil {
			if h.DefaultUpstream != "" {
				return params, nil // Will use DefaultUpstream
			}
			return nil, err
		}
	case "header":
		value = r.Header.Get(h.HeaderName)
		if value == "" {
			if h.DefaultUpstream != "" {
				return params, nil // Will use DefaultUpstream
			}
			return nil, fmt.Errorf("header %s not found or empty", h.HeaderName)
		}
	case "query_param":
		value = r.URL.Query().Get(h.QueryParam)
		if value == "" {
			if h.DefaultUpstream != "" {
				return params, nil // Will use DefaultUpstream
			}
			return nil, fmt.Errorf("query parameter %s not found or empty", h.QueryParam)
		}
	case "static":
		// No parameter to extract
		return params, nil
	default:
		return nil, fmt.Errorf("unknown method: %s", h.Method)
	}

	params["value"] = value
	return params, nil
}

// extractParameter extracts a single parameter from the request
func (h *Handler) extractParameter(r *http.Request, paramSource ParameterSource) (string, error) {
	switch paramSource.Type {
	case "path_regex":
		if paramSource.RegexPattern == nil {
			return "", errors.New("regex pattern not compiled")
		}
		matches := paramSource.RegexPattern.FindStringSubmatch(r.URL.Path)
		if len(matches) < 2 {
			return "", errors.New("no match found in path")
		}
		return matches[1], nil

	case "header":
		value := r.Header.Get(paramSource.Value)
		if value == "" {
			return "", fmt.Errorf("header %s not found or empty", paramSource.Value)
		}
		return value, nil

	case "query_param":
		value := r.URL.Query().Get(paramSource.Value)
		if value == "" {
			return "", fmt.Errorf("query parameter %s not found or empty", paramSource.Value)
		}
		return value, nil

	case "static":
		return paramSource.Value, nil

	default:
		return "", fmt.Errorf("unknown parameter type: %s", paramSource.Type)
	}
}

// determineProtocol determines which protocol to use based on configuration and parameters
func (h *Handler) determineProtocol(params map[string]string) (string, error) {
	// If we're using legacy configuration, default to WebSocket
	if h.Method != "" {
		return "ws", nil
	}

	// If protocol is configured as a parameter, extract from params
	if h.Protocol.IsParameter {
		protocol, ok := params[h.Protocol.Value]
		if !ok {
			if h.Protocol.Default != "" {
				return h.Protocol.Default, nil
			}
			return "", fmt.Errorf("protocol parameter %s not found", h.Protocol.Value)
		}

		// Validate the protocol
		switch protocol {
		case "ws", "tcp", "udp", "quic":
			return protocol, nil
		default:
			if h.Protocol.Default != "" {
				h.logger.Warn("invalid protocol value, using default",
					zap.String("value", protocol),
					zap.String("default", h.Protocol.Default))
				return h.Protocol.Default, nil
			}
			return "", fmt.Errorf("invalid protocol: %s", protocol)
		}
	}

	// Otherwise, use the static protocol
	return h.Protocol.Value, nil
}

// buildUpstreamAddress builds the upstream address/URL using the parameters
func (h *Handler) buildUpstreamAddress(params map[string]string) (string, error) {
	// If using legacy configuration and DefaultUpstream is set, use it
	if h.Method != "" && len(params) == 0 && h.DefaultUpstream != "" {
		return h.DefaultUpstream, nil
	}

	// If using legacy configuration, replace {value} in the template
	if h.Method != "" {
		if h.Method == "static" {
			return h.UpstreamTemplate, nil
		}

		value, ok := params["value"]
		if !ok {
			if h.DefaultUpstream != "" {
				return h.DefaultUpstream, nil
			}
			return "", errors.New("parameter value not found")
		}

		return strings.Replace(h.UpstreamTemplate, "{value}", value, -1), nil
	}

	// Replace all parameter placeholders in the template
	result := h.UpstreamTemplate
	for name, value := range params {
		placeholder := "{" + name + "}"
		result = strings.Replace(result, placeholder, value, -1)
	}

	return result, nil
}

// proxyWebSocket proxies the WebSocket connection to the upstream server
func (h *Handler) proxyWebSocket(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL, params map[string]string) error {
	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(h.DialTimeout),
	}

	// Apply upstream proxy if configured
	if h.UpstreamProxy.Type != "" && h.UpstreamProxy.Type != "none" {
		proxyDialer, err := h.createProxyDialer(dialer)
		if err != nil {
			return fmt.Errorf("failed to create proxy dialer: %w", err)
		}
		dialer = &net.Dialer{Timeout: time.Duration(h.DialTimeout)}
		contextDialer := proxyDialer.(proxy.ContextDialer)

		// Use the proxy dialer
		upstreamConn, err := contextDialer.DialContext(r.Context(), "tcp", upstreamURL.Host)
		if err != nil {
			h.logger.Error("failed to connect to upstream via proxy", zap.Error(err))
			return fmt.Errorf("failed to connect to upstream via proxy: %w", err)
		}

		return h.handleWebSocketConnection(w, r, upstreamConn, upstreamURL, params)
	}

	// Determine if we need to use TLS
	useTLS := upstreamURL.Scheme == "wss" || upstreamURL.Scheme == "https"

	// Connect to the upstream server
	var conn net.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: h.TLS.InsecureSkipVerify,
			ServerName:         h.TLS.ServerName,
		}

		if h.TLS.ServerName == "" {
			tlsConfig.ServerName = upstreamURL.Hostname()
		}

		conn, err = tls.DialWithDialer(dialer, "tcp", upstreamURL.Host, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", upstreamURL.Host)
	}

	if err != nil {
		h.logger.Error("failed to connect to upstream", zap.Error(err))
		return fmt.Errorf("failed to connect to upstream: %w", err)
	}

	return h.handleWebSocketConnection(w, r, conn, upstreamURL, params)
}

// handleWebSocketConnection handles the WebSocket connection after connecting to upstream
func (h *Handler) handleWebSocketConnection(w http.ResponseWriter, r *http.Request, upstreamConn net.Conn, upstreamURL *url.URL, params map[string]string) error {
	defer upstreamConn.Close()

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
		if len(h.ForwardHeaders) > 0 {
			// Only forward specific headers if configured
			for _, name := range h.ForwardHeaders {
				if strings.EqualFold(k, name) {
					for _, v := range vv {
						header.Add(k, v)
					}
					break
				}
			}
		} else {
			// Forward all headers by default
			for _, v := range vv {
				header.Add(k, v)
			}
		}
	}

	// Add custom headers
	for k, v := range h.AddHeaders {
		header.Set(k, v)
	}

	// Update the Host header to match the upstream URL
	header.Set("Host", upstreamURL.Host)

	// Add X-Forwarded-* headers
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior := header.Get("X-Forwarded-For"); prior != "" {
			header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			header.Set("X-Forwarded-For", clientIP)
		}
	}

	if proto := header.Get("X-Forwarded-Proto"); proto != "" {
		// Keep existing header
	} else if r.TLS != nil {
		header.Set("X-Forwarded-Proto", "https")
	} else {
		header.Set("X-Forwarded-Proto", "http")
	}

	h.logger.Debug("connecting to upstream websocket",
		zap.String("url", upstreamURL.String()),
		zap.Any("headers", header))

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
	if _, err := upstreamConn.Write([]byte(upgradeReq)); err != nil {
		h.logger.Error("failed to write upgrade request", zap.Error(err))
		return fmt.Errorf("failed to write upgrade request: %w", err)
	}

	// Read the response from the upstream server
	br := bufio.NewReader(upstreamConn)
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
		_, err := io.Copy(upstreamConn, clientConn)
		errCh <- err
	}()

	// Copy from upstream to client
	go func() {
		_, err := io.Copy(clientConn, upstreamConn)
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

// proxyTCP proxies the TCP connection to the upstream server
func (h *Handler) proxyTCP(w http.ResponseWriter, r *http.Request, upstreamAddress string, params map[string]string) error {
	// Ensure we have a Host:Port format
	if !strings.Contains(upstreamAddress, ":") {
		upstreamAddress += ":80" // Default to port 80 if not specified
	}

	// Parse the address to see if it has a scheme
	hasScheme := strings.Contains(upstreamAddress, "://")
	var host string

	if hasScheme {
		u, err := url.Parse(upstreamAddress)
		if err != nil {
			return fmt.Errorf("invalid upstream address: %w", err)
		}
		host = u.Host
	} else {
		host = upstreamAddress
	}

	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(h.DialTimeout),
	}

	// Apply upstream proxy if configured
	if h.UpstreamProxy.Type != "" && h.UpstreamProxy.Type != "none" {
		proxyDialer, err := h.createProxyDialer(dialer)
		if err != nil {
			return fmt.Errorf("failed to create proxy dialer: %w", err)
		}
		dialer = &net.Dialer{Timeout: time.Duration(h.DialTimeout)}
		contextDialer := proxyDialer.(proxy.ContextDialer)

		// Use the proxy dialer
		upstreamConn, err := contextDialer.DialContext(r.Context(), "tcp", host)
		if err != nil {
			h.logger.Error("failed to connect to upstream via proxy", zap.Error(err))
			return fmt.Errorf("failed to connect to upstream via proxy: %w", err)
		}

		return h.handleTCPConnection(w, r, upstreamConn)
	}

	// Determine if we need to use TLS based on the address or explicit config
	useTLS := (hasScheme && (strings.HasPrefix(upstreamAddress, "https://") ||
		strings.HasPrefix(upstreamAddress, "wss://"))) || h.TLS.Enabled

	// Connect to the upstream server
	var upstreamConn net.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: h.TLS.InsecureSkipVerify,
			ServerName:         h.TLS.ServerName,
		}

		if h.TLS.ServerName == "" && hasScheme {
			u, _ := url.Parse(upstreamAddress)
			tlsConfig.ServerName = u.Hostname()
		}

		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	} else {
		upstreamConn, err = dialer.Dial("tcp", host)
	}

	if err != nil {
		h.logger.Error("failed to connect to upstream", zap.Error(err))
		return fmt.Errorf("failed to connect to upstream: %w", err)
	}

	return h.handleTCPConnection(w, r, upstreamConn)
}

// handleTCPConnection handles a TCP connection after connecting to upstream
func (h *Handler) handleTCPConnection(w http.ResponseWriter, r *http.Request, upstreamConn net.Conn) error {
	defer upstreamConn.Close()

	h.logger.Debug("tcp connection established, hijacking connection")

	// Hijack the client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		return errors.New("webserver doesn't support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack client connection: %w", err)
	}
	defer clientConn.Close()

	// Send HTTP 200 OK to the client to establish the connection
	// This is needed because we're converting an HTTP connection to a raw TCP connection
	response := "HTTP/1.1 200 OK\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp\r\n" +
		"\r\n"

	if _, err := clientConn.Write([]byte(response)); err != nil {
		return fmt.Errorf("failed to write TCP upgrade response: %w", err)
	}

	h.logger.Debug("starting bidirectional proxy between client and upstream TCP")

	// Set up bidirectional copy
	errCh := make(chan error, 2)

	// Copy from client to upstream
	go func() {
		_, err := io.Copy(upstreamConn, clientConn)
		errCh <- err
	}()

	// Copy from upstream to client
	go func() {
		_, err := io.Copy(clientConn, upstreamConn)
		errCh <- err
	}()

	// Wait for one of the connections to close
	err = <-errCh
	if err != nil && !isConnectionClosed(err) {
		h.logger.Error("tcp proxy error", zap.Error(err))
	} else {
		h.logger.Debug("tcp connection closed", zap.Error(err))
	}

	return nil
}

// proxyUDP proxies UDP datagrams to the upstream server
func (h *Handler) proxyUDP(w http.ResponseWriter, r *http.Request, upstreamAddress string, params map[string]string) error {
	// Ensure we have a Host:Port format
	if !strings.Contains(upstreamAddress, ":") {
		upstreamAddress += ":53" // Default to port 53 (DNS) if not specified
	}

	// Parse the address to see if it has a scheme
	if strings.Contains(upstreamAddress, "://") {
		u, err := url.Parse(upstreamAddress)
		if err != nil {
			return fmt.Errorf("invalid upstream address: %w", err)
		}
		upstreamAddress = u.Host
	}

	h.logger.Debug("establishing UDP connection to upstream",
		zap.String("upstream", upstreamAddress))

	// Resolve the upstream address
	upstreamAddr, err := net.ResolveUDPAddr("udp", upstreamAddress)
	if err != nil {
		h.logger.Error("failed to resolve upstream UDP address", zap.Error(err))
		return fmt.Errorf("failed to resolve upstream UDP address: %w", err)
	}

	// Create a UDP connection to the upstream
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		h.logger.Error("failed to dial upstream UDP", zap.Error(err))
		return fmt.Errorf("failed to dial upstream UDP: %w", err)
	}
	defer upstreamConn.Close()

	// UDP proxying is more complex as we need to somehow establish a "session" over HTTP
	// Since HTTP is connection-oriented and UDP is not, we'll use a WebSocket as a transport

	// Inform client that we're switching to WebSocket for UDP transport
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// Upgrade the HTTP connection to WebSocket
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("failed to upgrade to WebSocket for UDP proxy", zap.Error(err))
		return fmt.Errorf("failed to upgrade to WebSocket for UDP proxy: %w", err)
	}
	defer wsConn.Close()

	h.logger.Debug("websocket upgraded for UDP proxy, starting bidirectional proxy")

	// Create a stop channel for the goroutines
	stop := make(chan struct{})
	defer close(stop)

	// Create an error channel
	errCh := make(chan error, 2)

	// Forward client messages to upstream UDP
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("panic in client->UDP routine: %v", r)
			}
		}()

		for {
			select {
			case <-stop:
				return
			default:
				// Read message from WebSocket
				_, message, err := wsConn.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						h.logger.Error("unexpected close error", zap.Error(err))
					}
					errCh <- err
					return
				}

				// Write to upstream UDP
				_, err = upstreamConn.Write(message)
				if err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Forward UDP responses back to client
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("panic in UDP->client routine: %v", r)
			}
		}()

		buffer := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
				// Set a read deadline to allow for stopping
				upstreamConn.SetReadDeadline(time.Now().Add(1 * time.Second))

				// Read from UDP
				n, _, err := upstreamConn.ReadFromUDP(buffer)
				if err != nil {
					// Ignore timeout errors, which we use for cancellation
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					errCh <- err
					return
				}

				// Write to WebSocket
				err = wsConn.WriteMessage(websocket.BinaryMessage, buffer[:n])
				if err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Wait for an error or a signal to stop
	err = <-errCh
	if isConnectionClosed(err) || websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		h.logger.Debug("UDP proxy connection closed normally")
		return nil
	}
	h.logger.Error("UDP proxy error", zap.Error(err))
	return fmt.Errorf("UDP proxy error: %w", err)
}

// proxyQUIC proxies QUIC connections to the upstream server
func (h *Handler) proxyQUIC(w http.ResponseWriter, r *http.Request, upstreamAddress string, params map[string]string) error {
	// QUIC proxying requires specialized libraries and is more complex
	// This is a placeholder implementation that returns an error
	return fmt.Errorf("QUIC proxying not implemented")
}

// createProxyDialer creates a dialer that uses an upstream proxy
func (h *Handler) createProxyDialer(forward *net.Dialer) (proxy.Dialer, error) {
	proxyURL, err := url.Parse(h.UpstreamProxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Add authentication if provided
	if h.UpstreamProxy.Username != "" || h.UpstreamProxy.Password != "" {
		if proxyURL.User == nil {
			proxyURL.User = url.UserPassword(h.UpstreamProxy.Username, h.UpstreamProxy.Password)
		}
	}

	switch h.UpstreamProxy.Type {
	case "http":
		return proxy.FromURL(proxyURL, forward)
	case "socks5":
		auth := &proxy.Auth{
			User:     h.UpstreamProxy.Username,
			Password: h.UpstreamProxy.Password,
		}
		return proxy.SOCKS5("tcp", proxyURL.Host, auth, forward)
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", h.UpstreamProxy.Type)
	}
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

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
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
		// Check for legacy configuration format
		if d.NextArg() {
			// Save legacy method and continue with old-style parsing
			h.Method = d.Val()

			if h.Method != "path_regex" && h.Method != "header" && h.Method != "query_param" && h.Method != "static" {
				return d.Errf("unknown method: %s", h.Method)
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
					var err error
					h.pathRegexPattern, err = regexp.Compile(h.PathRegex)
					if err != nil {
						return d.Errf("invalid regex pattern: %v", err)
					}

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

			return nil
		}

		// New-style configuration with multiple parameters and protocol support
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "upstream_template":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.UpstreamTemplate = d.Val()

			case "parameter":
				// Initialize Parameters map if not already done
				if h.Parameters == nil {
					h.Parameters = make(map[string]ParameterSource)
				}

				// Expecting parameter name as the first argument
				if !d.NextArg() {
					return d.ArgErr()
				}
				name := d.Val()

				// Parse the parameter configuration block
				param := ParameterSource{}
				for paramNesting := d.Nesting(); d.NextBlock(paramNesting); {
					switch d.Val() {
					case "type":
						if !d.NextArg() {
							return d.ArgErr()
						}
						param.Type = d.Val()
						if param.Type != "path_regex" && param.Type != "header" &&
							param.Type != "query_param" && param.Type != "static" {
							return d.Errf("unknown parameter type: %s", param.Type)
						}

					case "value":
						if !d.NextArg() {
							return d.ArgErr()
						}
						param.Value = d.Val()

					case "default":
						if !d.NextArg() {
							return d.ArgErr()
						}
						param.Default = d.Val()

					default:
						return d.Errf("unknown parameter subdirective '%s'", d.Val())
					}
				}

				// Validate the parameter
				if param.Type == "" {
					return d.Errf("parameter %s must have a type", name)
				}

				if param.Type == "path_regex" && param.Value != "" {
					var err error
					param.RegexPattern, err = regexp.Compile(param.Value)
					if err != nil {
						return d.Errf("invalid regex pattern for parameter %s: %v", name, err)
					}
				}

				// Add parameter to the map
				h.Parameters[name] = param

			case "protocol":
				for protocolNesting := d.Nesting(); d.NextBlock(protocolNesting); {
					switch d.Val() {
					case "value":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Protocol.Value = d.Val()

					case "is_parameter":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val := d.Val()
						if val == "true" || val == "yes" || val == "on" {
							h.Protocol.IsParameter = true
						} else if val == "false" || val == "no" || val == "off" {
							h.Protocol.IsParameter = false
						} else {
							return d.Errf("is_parameter must be true/false, got: %s", val)
						}

					case "default":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.Protocol.Default = d.Val()

					default:
						return d.Errf("unknown protocol subdirective '%s'", d.Val())
					}
				}

			case "tls":
				for tlsNesting := d.Nesting(); d.NextBlock(tlsNesting); {
					switch d.Val() {
					case "enabled":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val := d.Val()
						if val == "true" || val == "yes" || val == "on" {
							h.TLS.Enabled = true
						} else if val == "false" || val == "no" || val == "off" {
							h.TLS.Enabled = false
						} else {
							return d.Errf("enabled must be true/false, got: %s", val)
						}

					case "insecure_skip_verify":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val := d.Val()
						if val == "true" || val == "yes" || val == "on" {
							h.TLS.InsecureSkipVerify = true
						} else if val == "false" || val == "no" || val == "off" {
							h.TLS.InsecureSkipVerify = false
						} else {
							return d.Errf("insecure_skip_verify must be true/false, got: %s", val)
						}

					case "ca_file":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.CAFile = d.Val()

					case "cert_file":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.CertFile = d.Val()

					case "key_file":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.KeyFile = d.Val()

					case "server_name":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.ServerName = d.Val()

					default:
						return d.Errf("unknown tls subdirective '%s'", d.Val())
					}
				}

			case "upstream_proxy":
				for proxyNesting := d.Nesting(); d.NextBlock(proxyNesting); {
					switch d.Val() {
					case "type":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.UpstreamProxy.Type = d.Val()
						if h.UpstreamProxy.Type != "none" && h.UpstreamProxy.Type != "http" &&
							h.UpstreamProxy.Type != "socks5" {
							return d.Errf("unknown proxy type: %s", h.UpstreamProxy.Type)
						}

					case "url":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.UpstreamProxy.URL = d.Val()

					case "username":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.UpstreamProxy.Username = d.Val()

					case "password":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.UpstreamProxy.Password = d.Val()

					default:
						return d.Errf("unknown upstream_proxy subdirective '%s'", d.Val())
					}
				}

			case "forward_headers":
				// Initialize list if not already done
				if h.ForwardHeaders == nil {
					h.ForwardHeaders = []string{}
				}

				// Parse header names
				for d.NextArg() {
					h.ForwardHeaders = append(h.ForwardHeaders, d.Val())
				}

			case "add_headers":
				// Initialize map if not already done
				if h.AddHeaders == nil {
					h.AddHeaders = make(map[string]string)
				}

				// Parse header name and value pairs
				for addHeadersNesting := d.Nesting(); d.NextBlock(addHeadersNesting); {
					name := d.Val()
					if !d.NextArg() {
						return d.ArgErr()
					}
					value := d.Val()
					h.AddHeaders[name] = value
				}

			case "dial_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val := d.Val()
				duration, err := time.ParseDuration(val)
				if err != nil {
					return d.Errf("invalid duration for dial_timeout: %v", err)
				}
				h.DialTimeout = caddy.Duration(duration)

			default:
				return d.Errf("unknown directive '%s'", d.Val())
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
