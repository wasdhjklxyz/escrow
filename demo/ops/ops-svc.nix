# A service that authenticates with a key shipped in /etc. Rotating the key
# is a config change like any other: it goes through escrow.
{ pkgs, ... }:
{
  environment.etc."ops-svc/api.key" = {
    source = ./keys/api.key;
    mode = "0440";
    group = "ops";
  };

  systemd.services.ops-svc = {
    description = "ops service";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      DynamicUser = true;
      SupplementaryGroups = [ "ops" ];
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
  };
}
