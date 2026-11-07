"""Background recorder.

    python -m recorder install [--yes]   consent, create + trust the CA, start at login
    python -m recorder run [--fallback-proxy PORT]
    python -m recorder status
    python -m recorder rotate-ca [--yes]
    python -m recorder uninstall [--wipe]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import sys

from shared import db, keystore

CONSENT_TEXT = """\
Shadow Profile will record the network requests that apps on this computer send.

What happens if you agree:
  * A certificate that only this computer trusts is created and added to your
    user trust store, so the recorder can read encrypted traffic. Its private key
    is kept in your {store} and nowhere else. It expires after 30 days.
  * A background recorder starts each time you log in (no window).
    On Windows, Windows will ask for permission to start the capture driver.
  * Requests are saved in an encrypted file only your account can open.

What is never recorded:
  * System processes, and any app or site you mark "Don't track".
  * Passwords, login forms, cookie and authorization values (only keyed hashes).
  * Search queries.

Nothing is sent anywhere. You can uninstall at any time; that removes the
certificate and the login item.
"""

log = logging.getLogger("shadow.recorder")


def _quiet_logging() -> None:
    """Security checklist #9: no request logging in Python or mitmproxy.

    Only our own fixed-text messages reach stderr; mitmproxy's (which can name
    hosts) are dropped.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(lambda rec: rec.name.startswith("shadow"))
    handler.setFormatter(logging.Formatter("recorder: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.WARNING)


def _store_name() -> str:
    return "Windows Credential Manager" if sys.platform == "win32" else "macOS Keychain"


def _consent(yes: bool) -> bool:
    print(CONSENT_TEXT.format(store=_store_name()))
    if yes:
        return True
    try:
        return input("Type 'yes' to continue: ").strip().lower() == "yes"
    except EOFError:
        return False


def _set_status(conn, **fields) -> None:
    current = json.loads(db.get_setting(conn, "recorder_status", "{}") or "{}")
    current.update(fields)
    db.set_setting(conn, "recorder_status", json.dumps(current))


# ---------------------------------------------------------------------- commands

def cmd_install(args) -> int:
    from recorder import ca, service

    if not _consent(args.yes):
        print("Cancelled. Nothing was changed.")
        return 1
    conn = db.open_db()
    try:
        ca.provision()
        method = service.install()
    except Exception as exc:
        # Never leave a trusted certificate behind after a failed install.
        ca.remove()
        service.uninstall()
        print(f"Install failed and was rolled back: {exc}", file=sys.stderr)
        return 2
    db.set_setting(conn, "consent_at", str(db.now_ms()))
    _set_status(conn, installed=True)
    where = {"task": "a Task Scheduler logon task", "run_key": "your user's 'run at login' list",
             "launch_agent": "a LaunchAgent"}.get(method, method)
    print(f"Installed via {where}. The recorder is running in the background and starts at each login.")
    return 0


def cmd_rotate_ca(args) -> int:
    from recorder import ca

    if not _consent(args.yes):
        return 1
    ca.provision()
    print("New certificate installed; restart the recorder to use it.")
    return 0


def cmd_uninstall(args) -> int:
    from recorder import ca, service

    service.uninstall()
    ca.remove()
    if args.wipe:
        shutil.rmtree(db.data_dir(), ignore_errors=True)
        keystore.delete_all()
        print("Removed the certificate, the login item, the log and its keys.")
    else:
        print("Removed the certificate and the login item. Your log is kept (use --wipe to delete it).")
    return 0


def cmd_status(_args) -> int:
    from recorder import ca, service

    loaded = ca.load()
    conn = db.open_db()
    hb = db.get_setting(conn, "recorder_heartbeat_at")
    print(json.dumps({
        "service_installed": service.is_installed(),
        "service_binary_user_writable": service.command_is_user_writable(),
        "ca": None if loaded is None else {
            "valid": ca.is_valid(loaded[1]),
            "expires": loaded[1].not_valid_after_utc.isoformat(),
            "sha1": ca.fingerprint(loaded[1]),
        },
        "last_heartbeat_ms": int(hb) if hb else None,
        "requests_logged": conn.execute("SELECT count(*) FROM requests").fetchone()[0],
        "status": json.loads(db.get_setting(conn, "recorder_status", "{}") or "{}"),
    }, indent=2))
    return 0


def build_master(*, fallback_port: int | None, ca_material, data_dir, db_path=None,
                 db_key: bytes | None = None, hmac_key: bytes | None = None):
    """Create the mitmproxy master with our addon. Must run inside an event loop."""
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    from recorder import addon, ca, procinfo, rules

    ca_ready = ca_material is not None and ca.is_valid(ca_material[1])
    mitm_dir = data_dir / "mitm"  # only public DH parameters live here
    mitm_dir.mkdir(exist_ok=True)
    if ca_ready:
        ca.install_into_mitmproxy(*ca_material, dhparam_dir=mitm_dir)
    else:
        # Still never let mitmproxy create a CA on disk.
        key, cert = ca.generate()
        ca.install_into_mitmproxy(key, cert, dhparam_dir=mitm_dir)

    if fallback_port is None:
        procinfo.patch_local_redirector()
        mode = ["local"]
    else:
        mode = [f"regular@{fallback_port}"]

    opts = options.Options(
        mode=mode,
        listen_host="127.0.0.1",  # never listen on the network (checklist #3)
        confdir=str(mitm_dir),
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.options.update(
        ssl_insecure=False,            # checklist #11
        stream_large_bodies="2m",      # don't buffer huge uploads/downloads
        http3=False,
    )

    writer_conn = db.open_db(db_path, db_key)
    rules_conn = db.open_db(db_path, db_key)
    writer = addon.Writer(writer_conn)
    rulebook = rules.RuleBook(rules_conn, fallback_mode=fallback_port is not None)
    recorder = addon.ShadowRecorder(rulebook, writer, hmac_key or keystore.hmac_key(), ca_ready=ca_ready)
    master.addons.add(recorder)
    _set_status(writer_conn, mode=mode[0], ca_ready=ca_ready, last_error=None, started_at=db.now_ms())
    return master, writer


def cmd_run(args) -> int:
    import os

    from recorder import ca, service

    _quiet_logging()
    service.pid_file().write_text(str(os.getpid()))  # lets uninstall stop us
    material = ca.load()
    if material is None or not ca.is_valid(material[1]):
        log.warning("certificate missing or expired: recording metadata only")
    writer = None

    async def run() -> None:
        nonlocal writer
        master, writer = build_master(fallback_port=args.fallback_proxy, ca_material=material,
                                      data_dir=db.data_dir())
        writer.start()
        await master.run()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        if writer is not None:
            _set_status(writer.conn, last_error=type(exc).__name__)
        log.warning("recorder stopped: %s", type(exc).__name__)
        return 1
    finally:
        if writer is not None and writer.is_alive():
            writer.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="recorder", description="Shadow Profile background recorder")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("install")
    i.add_argument("--yes", action="store_true", help="consent was given in the app")
    r = sub.add_parser("run")
    r.add_argument("--fallback-proxy", type=int, metavar="PORT",
                   help="use a system-proxy listener on 127.0.0.1:PORT instead of local capture mode")
    sub.add_parser("status")
    rc = sub.add_parser("rotate-ca")
    rc.add_argument("--yes", action="store_true")
    u = sub.add_parser("uninstall")
    u.add_argument("--wipe", action="store_true", help="also delete the log and its keys")
    args = p.parse_args(argv)
    return {"install": cmd_install, "run": cmd_run, "status": cmd_status,
            "rotate-ca": cmd_rotate_ca, "uninstall": cmd_uninstall}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
