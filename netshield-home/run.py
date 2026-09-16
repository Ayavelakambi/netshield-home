"""NetShield Home — entrypoint.

    python run.py [--host 0.0.0.0] [--port 5000] [--debug]

On first run with an empty database the app creates an 'admin' account with
a random password, prints it ONCE to the console, and forces a password
change on first login. (Use create_db.py to choose the password up front.)
"""
from __future__ import annotations

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
from netshield import create_app  # noqa: E402
from netshield.version import BUILD_DATE, VERSION  # noqa: E402


def _port_is_free(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(1.0)
        try:
            probe.connect(("127.0.0.1", port))
            return False
        except OSError:
            return True
    finally:
        probe.close()


def _check_port_free(port: int) -> None:
    """Refuse to start when another process already listens on the port.

    The #1 cause of "I updated but nothing changed" is a stale NetShield
    process still serving the old code on the same port. Fail loudly here
    instead of letting the old process keep running silently.

    Exception: when started by the in-app "restart as Administrator" flow
    (NETSHIELD_ELEVATE_RELAUNCH=1), wait up to 30s for the old instance to
    release the port, then proceed.
    """
    wait = 30 if os.environ.get("NETSHIELD_ELEVATE_RELAUNCH") == "1" else 0
    import time as _time
    deadline = _time.time() + wait
    while not _port_is_free(port):
        if _time.time() >= deadline:
            print("=" * 64)
            print("  ERROR: port %d is already in use." % port)
            print("  Another NetShield Home instance is still running and")
            print("  serving the OLD code — that is why changes don't appear.")
            print("  Stop it first:")
            print("    - close the old terminal window (Ctrl+C), or")
            print("    - Windows: taskkill /F /PID <pid>   (find it with:")
            print("                netstat -ano | findstr :%d)" % port)
            print("  Then run this command again.")
            print("=" * 64)
            sys.exit(1)
        print("  waiting for the previous instance to release port %d..." % port)
        _time.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("NETSHIELD_HOST",
                                                         "0.0.0.0"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("NETSHIELD_PORT", 5000)))
    parser.add_argument("--debug", action="store_true",
                        default=os.environ.get("NETSHIELD_DEBUG") == "1")
    parser.add_argument("--elevate", action="store_true",
                        help="restart with administrator privileges "
                             "(Windows UAC); on Linux/macOS run with sudo")
    args = parser.parse_args()

    from netshield.services.privileges import (is_elevated, privilege_status,
                                               relaunch_as_admin)

    if args.elevate:
        if is_elevated():
            print("Already running with administrator privileges.")
        elif os.name == "nt":
            ok, msg = relaunch_as_admin(args.port)
            print(msg)
            sys.exit(0 if ok else 1)
        else:
            print("Run with: sudo python run.py")
            sys.exit(1)

    _check_port_free(args.port)

    app = create_app()
    app.config["WEB_PORT"] = args.port

    first_run = app.config.get("FIRST_RUN_ADMIN")
    priv = privilege_status()
    print()
    print("NetShield Home v%s (%s)" % (VERSION, BUILD_DATE))
    print(f"  URL      : http://{args.host}:{args.port}")
    print(f"  Network  : {config.current_network()}  (gateway "
          f"{config.gateway_ip()}, host {config.detect_host_ip()})")
    if priv["elevated"]:
        print("  Privileges : ADMINISTRATOR/root ✓ — full packet features")
    else:
        print("  Privileges : NOT elevated — port scanning, traffic control")
        print("               and DNS sniffing are disabled. Run as")
        print("               Administrator (Windows, install Npcap) or:")
        print("               sudo python run.py   (Linux/macOS)")
    if os.name == "nt" and priv["npcap"] is False:
        print("  Npcap      : NOT INSTALLED — install from https://npcap.com")
    print("  UI check : the sidebar shows v%s — if it shows an older version,"
          % VERSION)
    print("             an old process is still running; stop it and restart.")
    print()

    from netshield.extensions import socketio
    socketio.run(app, host=args.host, port=args.port, debug=args.debug,
                 allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
