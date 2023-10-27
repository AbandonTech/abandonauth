{
  description = "Authentic Auth Service... Provides identification of a user from multiple external services.";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # see https://github.com/nix-community/poetry2nix/tree/master#api for more functions and examples.
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (import poetry2nix { inherit pkgs; }) mkPoetryApplication;
      in
      {
        packages = {
          abandonauth = mkPoetryApplication { projectDir = self; };
          default = self.packages.${system}.abandonauth;
        };

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.poetry ];
        };
      });
}
