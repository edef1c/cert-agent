{ pkgs, ... }:
let
    pkg = pkgs.callPackage ./package.nix {};
in {
    systemd.user = {
        services.ssh-agent = {
            environment.SSH_AUTH_SOCK = "%t/gnupg/S.gpg-agent.ssh";
            unitConfig.ConditionPathExists = "%h/.ssh/certificates";
            unitConfig.Requires = [ "ssh-agent.socket" "gpg-agent-ssh.socket" ];
            serviceConfig.ExecStart = "${pkg.bin}/bin/cert-agent %h/.ssh/certificates";
        };
        sockets.ssh-agent = {
            wantedBy = [ "sockets.target" ];
            socketConfig.SocketMode = "0700";
            socketConfig.DirectoryMode = "0700";
            socketConfig.ListenStream = "%t/ssh-agent";
        };
    };
    environment.interactiveShellInit = ''
      if [ -z "$SSH_AUTH_SOCK" ]; then
        export SSH_AUTH_SOCK=''${XDG_RUNTIME_DIR:-/run/user/`id -u`}/ssh-agent
      fi
    '';
}
