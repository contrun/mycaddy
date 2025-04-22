package wspproxy

import (
	"net/http/httptest"
	"testing"

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

			if h.Method != tt.want.Method {
				t.Errorf("Method = %v, want %v", h.Method, tt.want.Method)
			}
			if h.UpstreamTemplate != tt.want.UpstreamTemplate {
				t.Errorf("UpstreamTemplate = %v, want %v", h.UpstreamTemplate, tt.want.UpstreamTemplate)
			}
			if h.PathRegex != tt.want.PathRegex {
				t.Errorf("PathRegex = %v, want %v", h.PathRegex, tt.want.PathRegex)
			}
			if h.HeaderName != tt.want.HeaderName {
				t.Errorf("HeaderName = %v, want %v", h.HeaderName, tt.want.HeaderName)
			}
			if h.QueryParam != tt.want.QueryParam {
				t.Errorf("QueryParam = %v, want %v", h.QueryParam, tt.want.QueryParam)
			}
			if h.DefaultUpstream != tt.want.DefaultUpstream {
				t.Errorf("DefaultUpstream = %v, want %v", h.DefaultUpstream, tt.want.DefaultUpstream)
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
			name: "valid configuration",
			caddyfile: `
			wspproxy path_regex {
				upstream_template ws://example.com/{value}/ws
				path_regex /chat/([^/]+)
			}`,
			wantErr: false,
		},
		{
			name: "invalid configuration",
			caddyfile: `
			wspproxy {
				unknown_directive value
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
