package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/abiosoft/caddy-json-schema"
	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddyserver/replace-response"

	// _ "github.com/contrun/mycaddy/pkg/postgres-storage"
	_ "github.com/greenpau/caddy-security"
	_ "github.com/imgk/caddy-trojan"
	_ "github.com/mholt/caddy-l4"
	_ "github.com/mholt/dhall-adapter"
	_ "github.com/mohammed90/caddy-storage-loader"
	_ "github.com/techknowlogick/certmagic-s3"
)

func main() {
	caddycmd.Main()
}
