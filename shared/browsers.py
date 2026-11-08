"""Is an app a web browser, and which engine does it use?

Browsers and other apps are audited differently: a browser's traffic is made of
pages you visit (each with its own trackers), while an app phones home to its
maker and to the SDKs bundled inside it (crash reporting, analytics).

- macOS: a browser registers as a handler for http/https URLs in its Info.plist
  (``CFBundleURLTypes``). Electron apps (Discord, Slack, VS Code) register only
  their own schemes, so they correctly count as apps.
- Windows: the browsers listed under ``StartMenuInternet``.
- Fallback: well-known bundle ids and executable names.
"""

from __future__ import annotations

import plistlib
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

KNOWN_BUNDLE_IDS = {
    "com.google.chrome": "chromium", "com.google.chrome.canary": "chromium", "org.chromium.chromium": "chromium",
    "com.brave.browser": "chromium", "com.microsoft.edgemac": "chromium", "company.thebrowser.browser": "chromium",
    "com.vivaldi.vivaldi": "chromium", "com.operasoftware.opera": "chromium", "org.mozilla.firefox": "gecko",
    "org.mozilla.firefoxdeveloperedition": "gecko", "org.mozilla.nightly": "gecko", "app.zen-browser.zen": "gecko",
    "io.gitlab.librewolf-community": "gecko", "org.torproject.torbrowser": "gecko", "com.apple.safari": "webkit",
}
KNOWN_EXES = {
    "chrome": "chromium", "msedge": "chromium", "brave": "chromium", "vivaldi": "chromium", "opera": "chromium",
    "arc": "chromium", "firefox": "gecko", "zen": "gecko", "librewolf": "gecko", "waterfox": "gecko",
}
ENGINE_HINTS = {
    "gecko": ("Firefox-based browsers use their own certificate list. In about:config, set "
              "security.enterprise_roots.enabled to true so they trust Doppel's certificate, "
              "or the audit falls back to metadata only."),
    "webkit": "Safari loads pages in shared system processes, so it can't be audited. Use another browser.",
}


@dataclass(frozen=True)
class BrowserInfo:
    is_browser: bool
    engine: str | None = None  # "chromium" | "gecko" | "webkit" | None

    @property
    def hint(self) -> str | None:
        return ENGINE_HINTS.get(self.engine or "") if self.is_browser else None


NOT_A_BROWSER = BrowserInfo(False)


def _mac(bundle: Path) -> BrowserInfo:
    try:
        with open(bundle / "Contents" / "Info.plist", "rb") as f:
            info = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return NOT_A_BROWSER
    schemes = {str(s).lower() for t in info.get("CFBundleURLTypes") or [] for s in t.get("CFBundleURLSchemes") or []}
    known = KNOWN_BUNDLE_IDS.get(str(info.get("CFBundleIdentifier", "")).lower())
    if not ({"http", "https"} & schemes or known):
        return NOT_A_BROWSER
    if (bundle / "Contents" / "MacOS" / "XUL").exists():
        engine = "gecko"
    elif known:
        engine = known
    else:
        frameworks = bundle / "Contents" / "Frameworks"
        chromium = frameworks.is_dir() and any("Chrom" in p.name or p.name.endswith(" Framework.framework")
                                               for p in frameworks.iterdir())
        engine = "chromium" if chromium else None
    return BrowserInfo(True, engine)


def _windows(exe: str) -> BrowserInfo:
    stem = PureWindowsPath(exe).stem.lower()
    if stem in KNOWN_EXES:
        return BrowserInfo(True, KNOWN_EXES[stem])
    try:
        import winreg

        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            with winreg.OpenKey(hive, r"SOFTWARE\Clients\StartMenuInternet") as root:
                for i in range(winreg.QueryInfoKey(root)[0]):
                    name = winreg.EnumKey(root, i)
                    with winreg.OpenKey(root, rf"{name}\shell\open\command") as cmd:
                        if exe.lower() in str(winreg.QueryValue(cmd, None)).lower():
                            return BrowserInfo(True, None)
    except OSError:
        pass
    return NOT_A_BROWSER


def detect(path: str | None) -> BrowserInfo:
    if not path:
        return NOT_A_BROWSER
    if path.endswith(".app"):
        return _mac(Path(path))
    if sys.platform == "win32" or "\\" in path:
        return _windows(path)
    return NOT_A_BROWSER
