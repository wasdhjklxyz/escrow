{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.stdenv.mkDerivation {
            pname = "escrow";
            version = "0.1.0";
            src = self;
            nativeBuildInputs = with pkgs; [ cmake ];
            meta.platforms = pkgs.lib.platforms.linux;
          };
        }
      );

      devShells = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            name = "escrow";
            packages = with pkgs; [ clang-tools ];
            inputsFrom = [ self.packages.${system}.default ];
            shellHook = ''
              git config core.hooksPath .githooks
            '';
          };
        }
      );
    };
}
