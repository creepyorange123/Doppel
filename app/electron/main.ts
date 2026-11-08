import { app, BrowserWindow, dialog, ipcMain, nativeTheme, session, shell } from "electron";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { AnalyzerClient, pythonExecutable, repoRoot } from "./analyzer";
import { AuditController } from "./audit";
import {
  isAuditAction,
  isRecorderAction,
  isRendererRequestType,
  type AnalyzerEvent,
  type AuditControlResult,
  type RecorderResult,
} from "../src/shared/protocol";

let win: BrowserWindow | null = null;
let analyzer: AnalyzerClient | null = null;
let audits: AuditController | null = null;

function sendEvent(event: AnalyzerEvent): void {
  win?.webContents.send("shadow:event", event);
}

function createWindow(): void {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 720,
    minHeight: 480,
    title: "Doppel",
    // Matches --ground in src/styles.css so there is no flash before the page paints.
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#12151d" : "#eef0f3",
    webPreferences: {
      // Security checklist #5.
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  // The window only ever shows our bundled page.
  win.webContents.on("will-navigate", (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    // Only https links (e.g. opt-out pages, phase 6) go to the system browser.
    if (url.startsWith("https://")) void shell.openExternal(url);
    return { action: "deny" };
  });

  void win.loadFile(path.join(__dirname, "..", "..", "dist", "index.html"));
  win.on("closed", () => (win = null));

  // `npm run smoke`: load the window, print what it shows, then quit (Phase 0 check).
  if (process.argv.includes("--smoke-test")) {
    win.webContents.once("did-finish-load", () => {
      setTimeout(async () => {
        const text = await win?.webContents.executeJavaScript("document.body.innerText");
        console.log("SMOKE-TEST WINDOW TEXT:\n" + text);
        app.quit();
      }, 4000);
    });
  }
}

app.whenReady().then(() => {
  // The renderer makes no network requests at all; deny any that slip through,
  // and deny every permission (camera, notifications, ...).
  session.defaultSession.webRequest.onBeforeRequest((details, cb) => {
    const ok = details.url.startsWith("file://") || details.url.startsWith("devtools://");
    cb({ cancel: !ok });
  });
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));

  analyzer = new AnalyzerClient(sendEvent);
  analyzer.start();
  audits = new AuditController(() => analyzer, sendEvent);

  ipcMain.handle("shadow:request", async (event, type: unknown, payload: unknown) => {
    // Only our own window may call, and only allowlisted message types.
    if (!win || event.sender !== win.webContents) throw new Error("forbidden");
    // create_audit / finish_audit are main-only: audits start through shadow:audit.
    if (!isRendererRequestType(type)) throw new Error("unknown request type");
    const body = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {};
    return analyzer!.request(type, body as Record<string, unknown>);
  });

  ipcMain.handle("shadow:recorder", async (event, action: unknown): Promise<RecorderResult> => {
    if (!win || event.sender !== win.webContents) throw new Error("forbidden");
    if (!isRecorderAction(action)) throw new Error("unknown recorder action");
    // install: the user already agreed on the consent screen, so pass --yes.
    const args = action === "install" ? ["install", "--yes"] : [action];
    return runRecorder(args);
  });

  // Saves an exported blocklist to a file the user picks. Only text, only where they choose.
  ipcMain.handle("shadow:save", async (event, filename: unknown, content: unknown): Promise<boolean> => {
    if (!win || event.sender !== win.webContents) throw new Error("forbidden");
    if (typeof content !== "string" || content.length > 1_000_000) throw new Error("bad content");
    const name = typeof filename === "string" ? path.basename(filename).replace(/[^\w.-]/g, "-").slice(0, 100) : "";
    const res = await dialog.showSaveDialog(win, { defaultPath: name || "doppel-blocklist.txt" });
    if (res.canceled || !res.filePath) return false;
    await writeFile(res.filePath, content, { encoding: "utf8", mode: 0o644 });
    return true;
  });

  ipcMain.handle("shadow:audit", async (event, action: unknown, payload: unknown): Promise<AuditControlResult> => {
    if (!win || event.sender !== win.webContents) throw new Error("forbidden");
    if (!isAuditAction(action)) throw new Error("unknown audit action");
    const a = audits!;
    if (action === "start") return a.start(payload);
    if (action === "self") return a.self(payload);
    if (action === "stop") return a.stop();
    return a.state();
  });

  createWindow();
});

function runRecorder(args: string[]): Promise<RecorderResult> {
  const root = repoRoot();
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.PYTHONPATH;
  delete env.PYTHONSTARTUP;
  return new Promise((resolve) => {
    execFile(
      pythonExecutable(root),
      ["-s", "-m", "recorder", ...args],
      { cwd: root, env, windowsHide: true, timeout: 5 * 60 * 1000 },
      (err, stdout, stderr) => resolve({ ok: !err, output: (err ? stderr || String(err) : stdout).slice(0, 4000) }),
    );
  });
}

app.on("web-contents-created", (_e, contents) => {
  contents.on("will-attach-webview", (e) => e.preventDefault());
});

// Audits never outlive Doppel.
app.on("before-quit", () => audits?.shutdown());

app.on("window-all-closed", () => {
  audits?.shutdown();
  analyzer?.stop();
  app.quit();
});
