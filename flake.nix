{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix.url = "github:nix-community/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      gomod2nix,
      ...
    }:
    with flake-utils.lib;
    eachSystem defaultSystems (system: rec {
      pkgsOriginal = import nixpkgs { inherit system; };
      pkgsWithOverlays = import nixpkgs {
        inherit system;
        overlays = [ (import "${gomod2nix}/overlay.nix") ];
      };

      devShells = {
        ci =
          with pkgsWithOverlays;
          mkShell {
            buildInputs = [
              go
              gomod2nix.packages.${system}.default
            ];
            CGO_ENABLED = 0;
          };
        default =
          with pkgsWithOverlays;
          mkShell {
            buildInputs = [
              go
              gomod2nix.packages.${system}.default
            ];
          };
      };

      apps = rec {
        default = caddy;
        caddy = {
          type = "app";
          program = "${self.packages."${system}".caddy}/bin/caddy";
        };
      };
      defaultApp = apps.default;

      packages = rec {
        default = caddy;
        caddy =
          with pkgsWithOverlays;
          buildGoApplication {
            pname = "caddy";
            version = "latest";
            goPackagePath = "github.com/contrun/mycaddy/cmd/caddy";
            src = ./cmd/caddy;
            modules = ./cmd/caddy/gomod2nix.toml;
            CGO_ENABLED = 0;
          };
      };
      defaultPackage = packages.default;
    });
}
