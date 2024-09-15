{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix.url = "github:tweag/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, gomod2nix, ... }@inputs:
    with flake-utils.lib;
    eachSystem defaultSystems (system: {
      config = {
        android_sdk.accept_license = true;
        allowUnfree = true;
      };
      pkgs = import nixpkgs { inherit system config; };

      pkgsToBuildLocalPackages = import nixpkgs {
        inherit system config;
        overlays = [ (import "${gomod2nix}/overlay.nix") ];
      };

      apps = {
        caddy = {
          type = "app";
          program = "${self.packages."${system}".caddy}/bin/caddy";
        };
      };

      defaultApp = apps.caddy;

      packages = {
        caddy = pkgsToBuildLocalPackages.buildGoApplication {
          pname = "caddy";
          version = "latest";
          goPackagePath = "github.com/contrun/infra/caddy";
          src = ./caddy;
          modules = ./caddy/gomod2nix.toml;
          nativeBuildInputs = [ pkgs.musl ];

          CGO_ENABLED = 0;

          ldflags =
            [ "-linkmode external" "-extldflags '-static -L${pkgs.musl}/lib'" ];
        };
      };
    });
}
