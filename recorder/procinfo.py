"""Which app opened a connection.

mitmproxy's local capture mode knows the process behind every redirected
connection (``Stream.get_extra_info("pid" | "process_name")``) but does not put
it on the flow. We wrap the redirector's stream handler to remember it, keyed
by the client's (address, port), and look it up in ``client_connected``.
"""

from __future__ import annotations

import ctypes
import sys
import threading
from dataclasses import dataclass

from recorder.rules import app_display_name


@dataclass(frozen=True)
class AppInfo:
    pid: int | None
    path: str | None
    name: str | None

    @property
    def known(self) -> bool:
        return bool(self.path or self.name)


UNKNOWN = AppInfo(None, None, None)

_lock = threading.Lock()
_by_peer: dict[tuple[str, int], AppInfo] = {}
_MAX_ENTRIES = 50_000


def _peer_key(peer) -> tuple[str, int] | None:
    try:
        return (str(peer[0]), int(peer[1]))
    except (TypeError, IndexError, ValueError):
        return None


def remember(peer, pid: int | None, process_name: str | None) -> None:
    key = _peer_key(peer)
    if key is None:
        return
    info = resolve(pid, process_name)
    with _lock:
        if len(_by_peer) > _MAX_ENTRIES:
            _by_peer.clear()
        _by_peer[key] = info


def take(peer) -> AppInfo:
    key = _peer_key(peer)
    if key is None:
        return UNKNOWN
    with _lock:
        return _by_peer.pop(key, UNKNOWN)


def resolve(pid: int | None, process_name: str | None) -> AppInfo:
    path = None
    if process_name and ("\\" in process_name or "/" in process_name):
        path = process_name
    elif pid:
        path = executable_path(pid)
    name = app_display_name(path) if path else (process_name or None)
    return AppInfo(pid, path, name)


def executable_path(pid: int) -> str | None:
    try:
        if sys.platform == "win32":
            return _win_path(pid)
        if sys.platform == "darwin":
            return _mac_path(pid)
    except Exception:
        return None
    return None


def _win_path(pid: int) -> str | None:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        size = ctypes.c_uint32(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        k32.CloseHandle(h)


def _mac_path(pid: int) -> str | None:
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    buf = ctypes.create_string_buffer(4096)
    n = libproc.proc_pidpath(pid, buf, ctypes.sizeof(buf))
    return buf.value.decode("utf-8", "replace") if n > 0 else None


def patch_local_redirector() -> None:
    """Wrap mitmproxy's local redirector so process info is recorded per connection."""
    from mitmproxy.proxy import mode_servers

    cls = mode_servers.LocalRedirectorInstance
    if getattr(cls, "_shadow_patched", False):
        return
    original = cls.redirector_handle_stream.__func__  # classmethod

    async def handle(klass, stream):
        try:
            remember(stream.get_extra_info("peername"), stream.get_extra_info("pid", None),
                     stream.get_extra_info("process_name", None))
        except Exception:
            pass
        await original(klass, stream)

    cls.redirector_handle_stream = classmethod(handle)  # type: ignore[method-assign]
    cls._shadow_patched = True  # type: ignore[attr-defined]
