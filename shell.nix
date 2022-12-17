{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; [
    git
    go_1_19
    gopls
    go-tools
    qemu
    OVMFFull
    OVMF
    netcat
  ];
}
