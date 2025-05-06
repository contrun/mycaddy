package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	
	// Explicitly import http handler modules
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	
	// Import our quicssh-proxy module
	_ "github.com/contrun/mycaddy/pkg/quicssh-proxy"
)

func main() {
	caddycmd.Main()
}