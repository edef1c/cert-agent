{ buildGoPackage }:
buildGoPackage {
    name = "cert-agent";
    goPackagePath = "github.com/edef1c/cert-agent";
    src = ./certs.go;
    goDeps = ./deps.nix;
    unpackPhase = ''
        sourceRoot=$PWD/src
        mkdir $sourceRoot
        cp $src src
    '';
}
