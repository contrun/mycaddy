{ admin.config.load
  =
  { adapter = "caddyfile"
  , key = "Caddyfile"
  , module = "storage"
  , storage =
    { connection_string = env:POSTGRES_URL as Text
    , module = "postgres"
    }
  }
, apps.trojan = { proxy.proxy = "no_proxy", upstream.upstream = "caddy" }
}
