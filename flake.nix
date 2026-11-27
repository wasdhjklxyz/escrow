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
      # A role policy for `escrow --role`: the role's buildEnv (the agent's
      # PATH is env/bin) and its full runtime closure, the only store paths
      # the jail can see. closureInfo is `nix path-info -r` at build time,
      # so escrow never evaluates Nix.
      lib.mkRole =
        pkgs:
        { name, tools }:
        let
          env = pkgs.buildEnv {
            name = "escrow-env-${name}";
            paths = tools;
          };
          closure = pkgs.closureInfo { rootPaths = [ env ]; };
        in
        pkgs.runCommand "escrow-role-${name}" { } ''
          { echo "env ${env}"; sed 's/^/store /' ${closure}/store-paths; } >$out
        '';

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
            nativeBuildInputs = with pkgs; [
              cmake
              makeWrapper
            ];
            # escrow implements no crypto: sha256sum, ssh-keygen and diff run
            # as helpers, pinned here rather than taken from the caller's PATH.
            postFixup = ''
              wrapProgram $out/bin/escrow --prefix PATH : ${
                pkgs.lib.makeBinPath [
                  pkgs.coreutils
                  pkgs.diffutils
                  pkgs.openssh
                ]
              }
            '';
            meta.platforms = pkgs.lib.platforms.linux;
          };

          # The test agents and escape cases, at env/share/escrow-tests.
          tests = pkgs.stdenvNoCC.mkDerivation {
            name = "escrow-tests";
            src = ./tests;
            installPhase = ''
              mkdir -p $out/share/escrow-tests
              cp -r agent escape $out/share/escrow-tests/
            '';
          };

          # The hostile test agent's toolbox: util-linux (mount, unshare),
          # attr (setfattr) and bash (/dev/tcp, /dev/udp) are there on purpose
          # so the escape cases really try. Dropping one turns its attempts
          # into ERROR (exit 127), not a silent pass.
          role-test = self.lib.mkRole pkgs {
            name = "test";
            tools = with pkgs; [
              attr
              bash
              coreutils
              findutils
              gnugrep
              gnused
              util-linux
              self.packages.${system}.tests
            ];
          };

          # The demo's scripted ops agent (demo/agent/ops-ticket.sh).
          role-demo = self.lib.mkRole pkgs {
            name = "demo";
            tools = with pkgs; [
              bash
              coreutils
              gnugrep
              gnused
              (writeShellApplication {
                name = "ops-ticket";
                runtimeInputs = [
                  coreutils
                  gnugrep
                  gnused
                ];
                text = builtins.readFile ./demo/agent/ops-ticket.sh;
              })
            ];
          };

          # A real coding agent: Claude Code, run with --net and --env
          # CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY. Unfree, so only that
          # package is allowed.
          role-claude =
            let
              unfree = import nixpkgs {
                inherit system;
                config.allowUnfreePredicate = p: pkgs.lib.getName p == "claude-code";
              };
            in
            self.lib.mkRole pkgs {
              name = "claude";
              tools = with pkgs; [
                bash
                cacert
                coreutils
                diffutils
                findutils
                git
                gnugrep
                gnused
                unfree.claude-code
              ];
            };

          # The web front end (web/), with escrow, the demo roles and the demo
          # workspace baked in: `nix run .#web -- serve --data DIR`. nix is
          # for `review --closures`, which systemd's PATH wouldn't have.
          web = pkgs.writeShellApplication {
            name = "escrow-web";
            runtimeInputs = with pkgs; [
              nix
              openssh
              util-linux # prlimit
            ];
            text = ''
              export ESCROW=${self.packages.${system}.default}/bin/escrow
              export ESCROW_WEB_ROLE_DEMO=${self.packages.${system}.role-demo}
              export ESCROW_WEB_ROLE_CLAUDE=${self.packages.${system}.role-claude}
              export ESCROW_WEB_ROLE_TEST=${self.packages.${system}.role-test}
              export ESCROW_WEB_WORKSPACE=${./demo/ops}
              exec ${pkgs.python3.interpreter} -I ${./web}/server.py "$@"
            '';
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
            packages = with pkgs; [
              attr
              clang-tools
              diffutils
              openssh
            ];
            inputsFrom = [ self.packages.${system}.default ];
            shellHook = ''
              git config core.hooksPath .githooks
            '';
          };
        }
      );
    };
}
