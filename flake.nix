{
  description = "Trying to build caddy with plugins declaratively for NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs
    , flake-utils
    , ...
    }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
      };
      lib = pkgs.lib;
      caddyWithPlugins = pkgs.callPackage ./pkg.nix { };
    in
    let
      # Caddy Layer4 modules
      l4CaddyModules = lib.lists.map
        (name: {
          inherit name;
          repo = "github.com/mholt/caddy-l4";
          version = "4f012d4517cf65b3a2da1308ec6e770c0cf0b656";
        }) [
        "layer4"
      ];
    in
    rec {
      packages.default = caddyWithManyPlugins;
      packages.baseCaddy = caddyWithPlugins.withPlugins { caddyModules = [ ]; };
      caddyWithManyPlugins = caddyWithPlugins.withPlugins {
        vendorHash = "sha256-QLd4TYx5urfyvSKoJb+XZ9DwRkxogncVpHc+YIwFjkM=";
        caddyModules =
          [
            {
              name = "caddy-json-schema";
              repo = "github.com/abiosoft/caddy-json-schema";
              version = "c4d6e132f3af8d5746ea07e4a3f8238727a76b60";
            }
            {
              name = "cloudflare";
              repo = "github.com/caddy-dns/cloudflare";
              version = "89f16b99c18ef49c8bb470a82f895bce01cbaece";
            }
            # {
            #   name = "certmagic-s3";
            #   repo = "github.com/techknowlogick/certmagic-s3";
            #   version = "aea945d0a811c16bb8e58e30030dd5e7e66d884b";
            # }
            {
              name = "postgres-storage";
              repo = "github.com/yroc92/postgres-storage";
              version = "276797aefe401b738781692d278a158c53b99208";
            }
            {
              name = "transform-encoder";
              repo = "github.com/caddyserver/transform-encoder";
              version = "f627fc4f76334b7aef8d4ed8c99c7e2bcf94ac7d";
            }
            {
              name = "connegmatcher";
              repo = "github.com/mpilhlt/caddy-conneg";
              version = "v0.1.4";
            }
          ]
          ++ l4CaddyModules;
      };
    });
}
