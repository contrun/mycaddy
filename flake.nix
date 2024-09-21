{
  description = "Trying to build caddy with plugins declaratively for NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    caddy-json-schema = {
      url = "github:abiosoft/caddy-json-schema";
      flake = false;
    };
    caddy-l4 = {
      url = "github:mholt/caddy-l4";
      flake = false;
    };
    cloudflare = {
      url = "github:caddy-dns/cloudflare";
      flake = false;
    };
    postgres-storage = {
      url = "github:yroc92/postgres-storage";
      flake = false;
    };
    replace-response = {
      url = "github:caddyserver/replace-response";
      flake = false;
    };
    transform-encoder = {
      url = "github:caddyserver/transform-encoder";
      flake = false;
    };
    caddy-conneg = {
      url = "github:mpilhlt/caddy-conneg";
      flake = false;
    };
  };

  outputs =
    { self
    , nixpkgs
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
      lockFile = builtins.fromJSON (builtins.readFile ./flake.lock);
      getModuleInfo = name:
        let
          locked = lockFile.nodes.${name}.locked;
          repo = "github.com/${locked.owner}/${locked.repo}";
          version = locked.rev;
        in
        {
          inherit name repo version;
        };
    in
    rec {
      defaultPackage = self.packages."${system}".default;

      packages.baseCaddy = caddyWithPlugins.withPlugins { caddyModules = [ ]; };

      packages.default = caddyWithManyPlugins;
      packages.mycaddy = caddyWithManyPlugins;
      packages.caddy = caddyWithManyPlugins;
      caddyWithManyPlugins = caddyWithPlugins.withPlugins {
        vendorHash = "sha256-nGMYh0niJYe18KTxz9YIuQPHU8HbcshrRNyHOGaEKys=";
        caddyModules = builtins.map getModuleInfo
          [
            "caddy-json-schema"
            "caddy-l4"
            "cloudflare"
            "postgres-storage"
            "replace-response"
            "transform-encoder"
            "caddy-conneg"
          ];
      };
    });
}
