package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddyserver/replace-response"
	_ "github.com/greenpau/caddy-security"
	_ "github.com/mholt/caddy-l4"
	_ "github.com/mohammed90/caddy-storage-loader"
	_ "github.com/techknowlogick/certmagic-s3"
)

func main() {
	caddycmd.Main()
}
