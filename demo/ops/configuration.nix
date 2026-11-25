# The demo host. A container profile keeps the build small: no bootloader,
# no kernel, no filesystems to declare.
{ pkgs, ... }:
{
  imports = [ ./ops-svc.nix ];

  boot.isContainer = true;
  networking.hostName = "ops";

  users.groups.ops = { };
  users.users.alice = {
    isNormalUser = true;
    extraGroups = [ "ops" ];
  };
  users.users.dana = {
    isNormalUser = true;
    extraGroups = [ ];
  };

  environment.systemPackages = [ ];

  system.stateVersion = "25.11";
}
