"""Audit recorder. Nothing runs in the background: the app starts an audit, which
runs this as its child process until the audit's end time.

    python -m recorder install [--yes]   consent, create + trust the CA (one time)
    python -m recorder audit --id N      record audit N until it ends or is stopped
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
import signal
import sys

from shared import audits, db, keystore

CONSENT_TEXT = """\
Shadow Profile records the network traffic of apps you choose, only while an
audit you started is running.

What happens if you agree:
  * A certificate that only this computer trusts is created and added to your
    user trust store, so audits can read the encrypted traffic of the apps you
    pick. Its private key is kept in your {store} and nowhere else. It expires
    after 30 days.
  * Nothing runs in the background. When you start an audit, only the apps you
    picked (and the processes they start) go through Doppel, until the time
    you chose. Everything else on your computer, including VPNs and ad blockers,
    is left alone.
  * Requests are saved in an encrypted file only your account can open.

What is never recorded:
  * Anything outside an audit, or from apps you didn't pick.
  * System processes, and any site you mark "Never record".
  * Passwords, login forms, cookie and authorization values (only keyed hashes).
  * Search queries.

Nothing is sent anywhere. You can remove the certificate at any time.
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
    except Exception as exc:
        # Never leave a trusted certificate behind after a failed install.
        ca.remove()
        print(f"Install failed and was rolled back: {exc}", file=sys.stderr)
        return 2
    service.remove_legacy_login_item()  # the old always-on recorder, if it was ever installed
    db.set_setting(conn, "consent_at", str(db.now_ms()))
    _set_status(conn, installed=True)
    print("Certificate installed. Nothing runs until you start an audit.")
    return 0


def cmd_rotate_ca(args) -> int:
    from recorder import ca

    if not _consent(args.yes):
        return 1
    ca.provision()
    print("New certificate installed; it is used from the next audit.")
    return 0


def cmd_uninstall(args) -> int:
    from recorder import ca, service

    service.stop_running()
    service.remove_legacy_login_item()
    ca.remove()
    if args.wipe:
        shutil.rmtree(db.data_dir(), ignore_errors=True)
        keystore.delete_all()
        print("Removed the certificate, the log and its keys.")
    else:
        conn = db.open_db()
        conn.execute("DELETE FROM settings WHERE key = 'consent_at'")
        print("Removed the certificate. Your audits are kept (use --wipe to delete them).")
    return 0


def cmd_status(_args) -> int:
    from recorder import ca, service

    loaded = ca.load()
    conn = db.open_db()
    audits.settle(conn)
    active = audits.running(conn)
    print(json.dumps({
        "running": service.is_running(),
        "audit": active.public() if active else None,
        "legacy_login_item": service.legacy_login_item_exists(),
        "ca": None if loaded is None else {
            "valid": ca.is_valid(loaded[1]),
            "expires": loaded[1].not_valid_after_utc.isoformat(),
            "sha1": ca.fingerprint(loaded[1]),
        },
        "requests_logged": conn.execute("SELECT count(*) FROM requests").fetchone()[0],
        "status": json.loads(db.get_setting(conn, "recorder_status", "{}") or "{}"),
    }, indent=2))
    return 0


def build_master(audit: audits.Audit, *, ca_material, data_dir, listen_port: int | None = None, db_path=None,
                 db_key: bytes | None = None, hmac_key: bytes | None = None, devlog=None, process_table=None):
    """Create the mitmproxy master for one audit. Must run inside an event loop.

    ``listen_port`` runs a plain proxy on 127.0.0.1 instead of the OS redirector.
    Tests only: the sending process is unknown there, so every connection counts
    as the audit's first app.
    """
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    from recorder import addon, ca, procinfo, rules
    from recorder.scope import Scope, process_table as default_table

    ca_ready = ca_material is not None and ca.is_valid(ca_material[1])
    mitm_dir = data_dir / "mitm"  # only public DH parameters live here
    mitm_dir.mkdir(exist_ok=True)
    if ca_ready:
        ca.install_into_mitmproxy(*ca_material, dhparam_dir=mitm_dir)
    else:
        # Still never let mitmproxy create a CA on disk.
        key, cert = ca.generate()
        ca.install_into_mitmproxy(key, cert, dhparam_dir=mitm_dir)

    scope = Scope(audit.apps, table=process_table or default_table, any_process=listen_port is not None)
    if listen_port is None:
        procinfo.patch_local_redirector()
        mode = [f"local:{scope.initial_spec()}"]
    else:
        mode = [f"regular@{listen_port}"]

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
    rulebook = rules.RuleBook(rules_conn)
    recorder = addon.ShadowRecorder(scope, rulebook, writer, hmac_key or keystore.hmac_key(),
                                    audit_id=audit.id, ca_ready=ca_ready, devlog=devlog)
    master.addons.add(recorder)
    _set_status(writer_conn, mode=mode[0].split(":")[0], ca_ready=ca_ready, last_error=None, started_at=db.now_ms())
    return master, writer, scope


async def _audit_clock(master, scope, ends_at: int, local: bool) -> None:
    """Refresh the process filter as apps spawn helpers; stop at the end time."""
    from recorder import addon
    from recorder.scope import REFRESH_SECONDS

    last = None
    while True:
        remaining = (ends_at - db.now_ms()) / 1000
        if remaining <= 0:
            master.shutdown()
            return
        await asyncio.sleep(min(remaining, REFRESH_SECONDS))
        spec = scope.refresh()  # ~1 ms; cheaper than handing it to a thread
        if local and spec != last:
            addon.set_intercept(spec)
            last = spec


def cmd_audit(args) -> int:
    import os

    from recorder import ca, service

    _quiet_logging()
    conn = db.open_db()
    try:
        audit = audits.get(conn, args.id)
    except audits.AuditError:
        log.warning("no such audit")
        return 2
    if audit.status != "running" or audit.ends_at <= db.now_ms():
        log.warning("that audit has already ended")
        return 2
    service.pid_file().write_text(str(os.getpid()))  # lets uninstall stop us
    material = ca.load()
    if material is None or not ca.is_valid(material[1]):
        log.warning("certificate missing or expired: recording metadata only")
    writer = None
    devlog = None
    if args.dev_traffic_log:
        from recorder import devlog as devlog_mod

        devlog = devlog_mod.TrafficLog(args.dev_traffic_log)
        log.warning("DEVELOPMENT: writing every connection in plaintext to %s. Delete it when done.", devlog.path)

    async def run() -> None:
        nonlocal writer
        master, writer, scope = build_master(audit, ca_material=material, data_dir=db.data_dir(), devlog=devlog)
        writer.start()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, master.shutdown)
            except (NotImplementedError, RuntimeError):  # Windows
                pass
        clock = asyncio.create_task(_audit_clock(master, scope, audit.ends_at, local=True))
        try:
            await master.run()
        finally:
            clock.cancel()

    status, error, code = "done", None, 0
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        status, error, code = "failed", f"The recorder stopped: {type(exc).__name__}", 1
        if writer is not None:
            _set_status(writer.conn, last_error=type(exc).__name__)
        log.warning("recorder stopped: %s", type(exc).__name__)
    finally:
        if writer is not None and writer.is_alive():
            writer.stop()
        if devlog is not None:
            devlog.close()
        audits.finish(conn, audit.id, status, error)
        service.pid_file().unlink(missing_ok=True)
    return code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="recorder", description="Shadow Profile audit recorder")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("install")
    i.add_argument("--yes", action="store_true", help="consent was given in the app")
    a = sub.add_parser("audit")
    a.add_argument("--id", type=int, required=True, help="the audit to record (created by the app)")
    a.add_argument("--dev-traffic-log", metavar="PATH",
                   help="DEVELOPMENT ONLY: also write every connection, with full URLs, to this plaintext file")
    sub.add_parser("status")
    rc = sub.add_parser("rotate-ca")
    rc.add_argument("--yes", action="store_true")
    u = sub.add_parser("uninstall")
    u.add_argument("--wipe", action="store_true", help="also delete the log and its keys")
    args = p.parse_args(argv)
    return {"install": cmd_install, "audit": cmd_audit, "status": cmd_status,
            "rotate-ca": cmd_rotate_ca, "uninstall": cmd_uninstall}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
