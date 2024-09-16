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
        vendorHash = "sha256-uvg2dthXS1lGthbwTJt+02pNnSOSS11u6ht3JKBPcR4=";
        caddyModules =
          [
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
