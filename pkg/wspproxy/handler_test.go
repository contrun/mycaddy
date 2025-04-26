package wspproxy

import (
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		caddyfile string
		want      Handler
		wantErr   bool
	}{
		// Legacy configurations
		{
			name: "path_regex method",
			caddyfile: `wspproxy path_regex {
				upstream_template ws://example.com/{value}/ws
				path_regex /chat/([^/]+)
			}`,
			want: Handler{
				Method:           "path_regex",
				UpstreamTemplate: "ws://example.com/{value}/ws",
				PathRegex:        "/chat/([^/]+)",
			},
			wantErr: false,
		},
		{
			name: "header method",
			caddyfile: `wspproxy header {
				upstream_template ws://{value}.example.com/ws
				header_name X-WS-Backend
				default_upstream ws://default.example.com/ws
			}`,
			want: Handler{
				Method:           "header",
				UpstreamTemplate: "ws://{value}.example.com/ws",
				HeaderName:       "X-WS-Backend",
				DefaultUpstream:  "ws://default.example.com/ws",
			},
			wantErr: false,
		},
		{
			name: "query_param method",
			caddyfile: `wspproxy query_param {
				upstream_template ws://{value}.example.com/ws
				query_param backend
			}`,
			want: Handler{
				Method:           "query_param",
				UpstreamTemplate: "ws://{value}.example.com/ws",
				QueryParam:       "backend",
			},
			wantErr: false,
		},
		{
			name: "static method",
			caddyfile: `wspproxy static {
				upstream_template ws://static.example.com/ws
			}`,
			want: Handler{
				Method:           "static",
				UpstreamTemplate: "ws://static.example.com/ws",
			},
			wantErr: false,
		},
		{
			name: "missing method",
			caddyfile: `wspproxy {
				upstream_template ws://example.com/ws
			}`,
			want:    Handler{},
			wantErr: true,
		},
		{
			name: "unknown directive",
			caddyfile: `wspproxy path_regex {
				upstream_template ws://example.com/{value}/ws
				path_regex /chat/([^/]+)
				unknown_directive value
			}`,
			want:    Handler{},
			wantErr: true,
		},

		// New-style configurations
		{
			name: "multiple parameters with tcp protocol",
			caddyfile: `wspproxy {
				upstream_template tcp://{host}:{port}
				
				parameter host {
					type header
					value X-Target-Host
					default example.com
				}
				
				parameter port {
					type query_param
					value port
					default 80
				}
				
				protocol {
					value tcp
					is_parameter false
				}
				
				tls {
					enabled true
					insecure_skip_verify true
				}
			}`,
			want: Handler{
				UpstreamTemplate: "tcp://{host}:{port}",
				Parameters: map[string]ParameterSource{
					"host": {
						Type:    "header",
						Value:   "X-Target-Host",
						Default: "example.com",
					},
					"port": {
						Type:    "query_param",
						Value:   "port",
						Default: "80",
					},
				},
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "tcp",
					IsParameter: false,
				},
				TLS: TLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true,
				},
			},
			wantErr: false,
		},
		{
			name: "dynamic protocol selection",
			caddyfile: `wspproxy {
				upstream_template {proto}://{host}:{port}
				
				parameter host {
					type path_regex
					value /([^/]+)/service
				}
				
				parameter port {
					type static
					value 8080
				}
				
				parameter proto {
					type query_param
					value proto
					default ws
				}
				
				protocol {
					value proto
					is_parameter true
					default ws
				}
			}`,
			want: Handler{
				UpstreamTemplate: "{proto}://{host}:{port}",
				Parameters: map[string]ParameterSource{
					"host": {
						Type:  "path_regex",
						Value: "/([^/]+)/service",
					},
					"port": {
						Type:  "static",
						Value: "8080",
					},
					"proto": {
						Type:    "query_param",
						Value:   "proto",
						Default: "ws",
					},
				},
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "proto",
					IsParameter: true,
					Default:     "ws",
				},
			},
			wantErr: false,
		},
		{
			name: "with upstream proxy",
			caddyfile: `wspproxy {
				upstream_template ws://{host}/ws
				
				parameter host {
					type header
					value X-Target
				}
				
				upstream_proxy {
					type socks5
					url socks5://proxy.example.com:1080
					username proxyuser
					password proxypass
				}
				
				add_headers {
					X-Forwarded-Host example.org
				}
				
				forward_headers Host Connection Upgrade
				
				dial_timeout 5s
			}`,
			want: Handler{
				UpstreamTemplate: "ws://{host}/ws",
				Parameters: map[string]ParameterSource{
					"host": {
						Type:  "header",
						Value: "X-Target",
					},
				},
				UpstreamProxy: UpstreamProxyConfig{
					Type:     "socks5",
					URL:      "socks5://proxy.example.com:1080",
					Username: "proxyuser",
					Password: "proxypass",
				},
				AddHeaders: map[string]string{
					"X-Forwarded-Host": "example.org",
				},
				ForwardHeaders: []string{"Host", "Connection", "Upgrade"},
				DialTimeout:    caddy.Duration(5 * time.Second),
			},
			wantErr: false,
		},
		{
			name: "invalid parameter type",
			caddyfile: `wspproxy {
				upstream_template ws://{host}/ws
				
				parameter host {
					type invalid_type
					value something
				}
			}`,
			want:    Handler{},
			wantErr: true,
		},
		{
			name: "invalid protocol value",
			caddyfile: `wspproxy {
				upstream_template ws://{host}/ws
				
				parameter host {
					type header
					value X-Target
				}
				
				protocol {
					value invalid_protocol
				}
			}`,
			want:    Handler{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Handler{}
			tokens, err := caddyfile.Tokenize([]byte(tt.caddyfile), "testfile")
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}
			dispenser := caddyfile.NewDispenser(tokens)
			err = h.UnmarshalCaddyfile(dispenser)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// For legacy configurations
			if h.Method != "" {
				if h.Method != tt.want.Method {
					t.Errorf("Method = %v, want %v", h.Method, tt.want.Method)
				}
				if h.UpstreamTemplate != tt.want.UpstreamTemplate {
					t.Errorf("UpstreamTemplate = %v, want %v", h.UpstreamTemplate)
				}
				if h.PathRegex != tt.want.PathRegex {
					t.Errorf("PathRegex = %v, want %v", h.PathRegex)
				}
				if h.HeaderName != tt.want.HeaderName {
					t.Errorf("HeaderName = %v, want %v", h.HeaderName)
				}
				if h.QueryParam != tt.want.QueryParam {
					t.Errorf("QueryParam = %v, want %v", h.QueryParam)
				}
				if h.DefaultUpstream != tt.want.DefaultUpstream {
					t.Errorf("DefaultUpstream = %v, want %v", h.DefaultUpstream, tt.want.DefaultUpstream)
				}
				return
			}

			// For new style configurations
			if h.UpstreamTemplate != tt.want.UpstreamTemplate {
				t.Errorf("UpstreamTemplate = %v, want %v", h.UpstreamTemplate, tt.want.UpstreamTemplate)
			}

			// Check parameters
			if len(h.Parameters) != len(tt.want.Parameters) {
				t.Errorf("Parameters count = %v, want %v", len(h.Parameters), len(tt.want.Parameters))
			}
			for name, param := range tt.want.Parameters {
				hParam, ok := h.Parameters[name]
				if !ok {
					t.Errorf("Parameter %s not found", name)
					continue
				}
				if hParam.Type != param.Type {
					t.Errorf("Parameter %s Type = %v, want %v", name, hParam.Type, param.Type)
				}
				if hParam.Value != param.Value {
					t.Errorf("Parameter %s Value = %v, want %v", name, hParam.Value, param.Value)
				}
				if hParam.Default != param.Default {
					t.Errorf("Parameter %s Default = %v, want %v", name, hParam.Default, param.Default)
				}
			}

			// Check protocol
			if h.Protocol.Value != tt.want.Protocol.Value {
				t.Errorf("Protocol.Value = %v, want %v", h.Protocol.Value, tt.want.Protocol.Value)
			}
			if h.Protocol.IsParameter != tt.want.Protocol.IsParameter {
				t.Errorf("Protocol.IsParameter = %v, want %v", h.Protocol.IsParameter, tt.want.Protocol.IsParameter)
			}
			if h.Protocol.Default != tt.want.Protocol.Default {
				t.Errorf("Protocol.Default = %v, want %v", h.Protocol.Default, tt.want.Protocol.Default)
			}

			// Check TLS
			if h.TLS.Enabled != tt.want.TLS.Enabled {
				t.Errorf("TLS.Enabled = %v, want %v", h.TLS.Enabled, tt.want.TLS.Enabled)
			}
			if h.TLS.InsecureSkipVerify != tt.want.TLS.InsecureSkipVerify {
				t.Errorf("TLS.InsecureSkipVerify = %v, want %v", h.TLS.InsecureSkipVerify, tt.want.TLS.InsecureSkipVerify)
			}

			// Check upstream proxy
			if tt.want.UpstreamProxy.Type != "" {
				if h.UpstreamProxy.Type != tt.want.UpstreamProxy.Type {
					t.Errorf("UpstreamProxy.Type = %v, want %v", h.UpstreamProxy.Type, tt.want.UpstreamProxy.Type)
				}
				if h.UpstreamProxy.URL != tt.want.UpstreamProxy.URL {
					t.Errorf("UpstreamProxy.URL = %v, want %v", h.UpstreamProxy.URL, tt.want.UpstreamProxy.URL)
				}
				if h.UpstreamProxy.Username != tt.want.UpstreamProxy.Username {
					t.Errorf("UpstreamProxy.Username = %v, want %v", h.UpstreamProxy.Username, tt.want.UpstreamProxy.Username)
				}
				if h.UpstreamProxy.Password != tt.want.UpstreamProxy.Password {
					t.Errorf("UpstreamProxy.Password = %v, want %v", h.UpstreamProxy.Password, tt.want.UpstreamProxy.Password)
				}
			}

			// Check add headers
			if len(tt.want.AddHeaders) > 0 {
				for k, v := range tt.want.AddHeaders {
					if h.AddHeaders[k] != v {
						t.Errorf("AddHeaders[%s] = %v, want %v", k, h.AddHeaders[k], v)
					}
				}
			}

			// Check forward headers
			if len(tt.want.ForwardHeaders) > 0 {
				if len(h.ForwardHeaders) != len(tt.want.ForwardHeaders) {
					t.Errorf("ForwardHeaders count = %v, want %v", len(h.ForwardHeaders), len(tt.want.ForwardHeaders))
				} else {
					for i, v := range tt.want.ForwardHeaders {
						if h.ForwardHeaders[i] != v {
							t.Errorf("ForwardHeaders[%d] = %v, want %v", i, h.ForwardHeaders[i], v)
						}
					}
				}
			}
		})
	}
}

func TestParameterExtraction(t *testing.T) {
	tests := []struct {
		name       string
		handler    Handler
		requestURL string
		headers    map[string]string
		want       map[string]string
		wantErr    bool
	}{
		{
			name: "path regex parameter",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"username": {
						Type:         "path_regex",
						Value:        "/users/([^/]+)",
						RegexPattern: regexp.MustCompile("/users/([^/]+)"),
					},
				},
			},
			requestURL: "https://example.com/users/alice",
			want: map[string]string{
				"username": "alice",
			},
			wantErr: false,
		},
		{
			name: "header parameter",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"backend": {
						Type:  "header",
						Value: "X-Backend",
					},
				},
			},
			requestURL: "https://example.com/api",
			headers: map[string]string{
				"X-Backend": "server1",
			},
			want: map[string]string{
				"backend": "server1",
			},
			wantErr: false,
		},
		{
			name: "query parameter",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"format": {
						Type:  "query_param",
						Value: "output",
					},
				},
			},
			requestURL: "https://example.com/api?output=json",
			want: map[string]string{
				"format": "json",
			},
			wantErr: false,
		},
		{
			name: "static parameter",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"version": {
						Type:  "static",
						Value: "v1",
					},
				},
			},
			requestURL: "https://example.com/api",
			want: map[string]string{
				"version": "v1",
			},
			wantErr: false,
		},
		{
			name: "multiple parameters",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"username": {
						Type:         "path_regex",
						Value:        "/users/([^/]+)",
						RegexPattern: regexp.MustCompile("/users/([^/]+)"),
					},
					"format": {
						Type:  "query_param",
						Value: "output",
					},
					"version": {
						Type:  "static",
						Value: "v1",
					},
				},
			},
			requestURL: "https://example.com/users/bob?output=xml",
			want: map[string]string{
				"username": "bob",
				"format":   "xml",
				"version":  "v1",
			},
			wantErr: false,
		},
		{
			name: "missing parameter with default",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"backend": {
						Type:    "header",
						Value:   "X-Backend",
						Default: "default-backend",
					},
				},
			},
			requestURL: "https://example.com/api",
			headers:    map[string]string{},
			want: map[string]string{
				"backend": "default-backend",
			},
			wantErr: false,
		},
		{
			name: "missing parameter without default",
			handler: Handler{
				Parameters: map[string]ParameterSource{
					"backend": {
						Type:  "header",
						Value: "X-Backend",
					},
				},
			},
			requestURL: "https://example.com/api",
			headers:    map[string]string{},
			want:       nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.requestURL, nil)

			// Add headers
			for name, value := range tt.headers {
				req.Header.Set(name, value)
			}

			params, err := tt.handler.extractParameters(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if len(params) != len(tt.want) {
				t.Errorf("extractParameters() got %d parameters, want %d", len(params), len(tt.want))
				return
			}

			for name, value := range tt.want {
				if params[name] != value {
					t.Errorf("extractParameters() params[%s] = %v, want %v", name, params[name], value)
				}
			}
		})
	}
}

func TestBuildUpstreamAddress(t *testing.T) {
	tests := []struct {
		name    string
		handler Handler
		params  map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "simple template",
			handler: Handler{
				UpstreamTemplate: "ws://{host}/ws",
			},
			params: map[string]string{
				"host": "example.com",
			},
			want:    "ws://example.com/ws",
			wantErr: false,
		},
		{
			name: "multiple parameters",
			handler: Handler{
				UpstreamTemplate: "tcp://{host}:{port}/{path}",
			},
			params: map[string]string{
				"host": "example.com",
				"port": "8080",
				"path": "api",
			},
			want:    "tcp://example.com:8080/api",
			wantErr: false,
		},
		{
			name: "repeated parameters",
			handler: Handler{
				UpstreamTemplate: "ws://{host}/ws?token={token}&user={username}&token={token}",
			},
			params: map[string]string{
				"host":     "example.com",
				"username": "alice",
				"token":    "abc123",
			},
			want:    "ws://example.com/ws?token=abc123&user=alice&token=abc123",
			wantErr: false,
		},
		{
			name: "protocol in parameter",
			handler: Handler{
				UpstreamTemplate: "{proto}://{host}:{port}",
			},
			params: map[string]string{
				"proto": "tcp",
				"host":  "example.com",
				"port":  "22",
			},
			want:    "tcp://example.com:22",
			wantErr: false,
		},
		{
			name: "legacy with path_regex",
			handler: Handler{
				Method:           "path_regex",
				UpstreamTemplate: "ws://example.com/{value}/ws",
			},
			params: map[string]string{
				"value": "chat",
			},
			want:    "ws://example.com/chat/ws",
			wantErr: false,
		},
		{
			name: "legacy with default upstream",
			handler: Handler{
				Method:           "path_regex",
				UpstreamTemplate: "ws://example.com/{value}/ws",
				DefaultUpstream:  "ws://default.example.com/ws",
			},
			params:  map[string]string{},
			want:    "ws://default.example.com/ws",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.handler.buildUpstreamAddress(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildUpstreamAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("buildUpstreamAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineProtocol(t *testing.T) {
	tests := []struct {
		name    string
		handler Handler
		params  map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "static protocol",
			handler: Handler{
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value: "ws",
				},
			},
			params:  map[string]string{},
			want:    "ws",
			wantErr: false,
		},
		{
			name: "protocol from parameter",
			handler: Handler{
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "proto",
					IsParameter: true,
				},
			},
			params: map[string]string{
				"proto": "tcp",
			},
			want:    "tcp",
			wantErr: false,
		},
		{
			name: "protocol from parameter with default",
			handler: Handler{
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "proto",
					IsParameter: true,
					Default:     "ws",
				},
			},
			params:  map[string]string{},
			want:    "ws",
			wantErr: false,
		},
		{
			name: "invalid protocol with default",
			handler: Handler{
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "proto",
					IsParameter: true,
					Default:     "ws",
				},
			},
			params: map[string]string{
				"proto": "invalid",
			},
			want:    "ws",
			wantErr: false,
		},
		{
			name: "missing protocol parameter without default",
			handler: Handler{
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "proto",
					IsParameter: true,
				},
			},
			params:  map[string]string{},
			want:    "",
			wantErr: true,
		},
		{
			name: "invalid protocol without default",
			handler: Handler{
				Protocol: struct {
					Value       string "json:\"value,omitempty\""
					IsParameter bool   "json:\"is_parameter,omitempty\""
					Default     string "json:\"default,omitempty\""
				}{
					Value:       "proto",
					IsParameter: true,
				},
			},
			params: map[string]string{
				"proto": "invalid",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "legacy configuration defaults to ws",
			handler: Handler{
				Method: "path_regex",
			},
			params:  map[string]string{},
			want:    "ws",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.handler.determineProtocol(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("determineProtocol() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("determineProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		caddyfile string
		wantErr   bool
	}{
		{
			name: "valid legacy configuration",
			caddyfile: `
			wspproxy path_regex {
				upstream_template ws://example.com/{value}/ws
				path_regex /chat/([^/]+)
			}`,
			wantErr: false,
		},
		{
			name: "valid new-style configuration",
			caddyfile: `
			wspproxy {
				upstream_template tcp://{host}:{port}
				
				parameter host {
					type header
					value X-Target-Host
				}
				
				parameter port {
					type query_param
					value port
					default 80
				}
				
				protocol {
					value tcp
				}
			}`,
			wantErr: false,
		},
		{
			name: "invalid legacy configuration",
			caddyfile: `
			wspproxy {
				unknown_directive value
			}`,
			wantErr: true,
		},
		{
			name: "invalid new-style configuration",
			caddyfile: `
			wspproxy {
				parameter host {
					type invalid_type
				}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := caddyfile.Tokenize([]byte(tt.caddyfile), "testfile")
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}
			d := caddyfile.NewDispenser(tokens)
			helper := httpcaddyfile.Helper{Dispenser: d}
			_, err = ParseCaddyfile(helper)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name: "valid websocket upgrade",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "Upgrade",
			},
			want: true,
		},
		{
			name: "mixed case headers",
			headers: map[string]string{
				"upgrade":    "WebSocket",
				"connection": "upgrade",
			},
			want: true,
		},
		{
			name: "connection contains multiple values",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "keep-alive, Upgrade",
			},
			want: true,
		},
		{
			name: "not a websocket upgrade",
			headers: map[string]string{
				"Connection": "keep-alive",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			for name, value := range tt.headers {
				r.Header.Set(name, value)
			}
			if got := isWebSocketUpgrade(r); got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}
