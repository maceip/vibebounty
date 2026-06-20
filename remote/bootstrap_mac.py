"""One-time: use the Mac password to authorize our SSH key, then report capabilities.

After this runs, all further access is key-based (no password needed).
Run:  uv run --with paramiko python remote/bootstrap_mac.py
"""
import os
import sys

import paramiko

HOST = os.environ.get("MAC_HOST", "192.168.1.33")
USER = os.environ.get("MAC_USER", "mac")
PASS = os.environ["MAC_PASS"]
PUBKEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnpPyNXuCaVj1ZMwLn2mDoiN060Aei0Nbl8KbAyvxBZ "
          "cactus-interop")


def run(cli: paramiko.SSHClient, cmd: str) -> str:
    _in, out, err = cli.exec_command(cmd, timeout=60)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    return (o + ("\n[stderr] " + e if e.strip() else "")).strip()


def main() -> None:
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(HOST, username=USER, password=PASS, timeout=15,
                look_for_keys=False, allow_agent=False)
    print("CONNECTED via password")

    # Authorize our key (idempotent).
    setup = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys && "
        f"grep -qF '{PUBKEY}' ~/.ssh/authorized_keys || echo '{PUBKEY}' >> ~/.ssh/authorized_keys && "
        "echo KEY_AUTHORIZED"
    )
    print(run(cli, setup))

    print("\n=== machine ===")
    print(run(cli, "uname -a; sysctl -n machdep.cpu.brand_string hw.memsize hw.ncpu 2>/dev/null; "
                   "sw_vers 2>/dev/null"))
    print("\n=== toolchain ===")
    print(run(cli, "echo SHELL=$SHELL; which brew python3 uv git 2>/dev/null; "
                   "python3 --version 2>/dev/null; "
                   "ls -d ~/.cargo 2>/dev/null; "
                   "python3 -c 'import mlx; print(\"mlx\", mlx.__version__)' 2>/dev/null || echo 'mlx: not installed'; "
                   "python3 -c 'import mlx_lm; print(\"mlx_lm ok\")' 2>/dev/null || echo 'mlx_lm: not installed'"))
    print("\n=== disk/home ===")
    print(run(cli, "echo HOME=$HOME; df -h ~ | tail -1; ls ~ | head -20"))
    cli.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
