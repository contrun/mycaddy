{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix.url = "github:nix-community/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, gomod2nix, ... }@inputs:
    with flake-utils.lib;
    eachSystem defaultSystems (system: rec {
      config = {
        android_sdk.accept_license = true;
        allowUnfree = true;
      };
      pkgsOriginal = import nixpkgs { inherit system config; };
      pkgsWithOverlays = import nixpkgs {
        inherit system config;
        overlays = [ (import "${gomod2nix}/overlay.nix") ];
      };

      devShells = {
        ci = with pkgsWithOverlays; mkShell {
          buildInputs = [ go gomod2nix.packages.${system}.default ];
          CGO_ENABLED = 0;
          ldflags =
            [ "-extldflags '-static -L${musl}/lib'" ];
        };
        default = with pkgsWithOverlays; mkShell {
          buildInputs = [ go gomod2nix.packages.${system}.default ];
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
        caddy = with pkgsWithOverlays; buildGoApplication {
          pname = "caddy";
          version = "latest";
          goPackagePath = "github.com/contrun/mycaddy/cmd/caddy";
          src = ./.;
          modules = ./gomod2nix.toml;
          nativeBuildInputs = [ musl ];

          CGO_ENABLED = 0;
          ldflags =
            [ "-extldflags '-static -L${musl}/lib'" ];
        };
      };
      defaultPackage = packages.default;
    });
}
