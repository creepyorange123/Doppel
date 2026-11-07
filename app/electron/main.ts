import { app, BrowserWindow, ipcMain, session, shell } from "electron";
import path from "node:path";
import { AnalyzerClient } from "./analyzer";
import { isRequestType, type AnalyzerEvent } from "../src/shared/protocol";

let win: BrowserWindow | null = null;
let analyzer: AnalyzerClient | null = null;

function sendEvent(event: AnalyzerEvent): void {
  win?.webContents.send("shadow:event", event);
}

function createWindow(): void {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    title: "Shadow Profile",
    backgroundColor: "#111316",
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

  ipcMain.handle("shadow:request", async (event, type: unknown, payload: unknown) => {
    // Only our own window may call, and only allowlisted message types.
    if (!win || event.sender !== win.webContents) throw new Error("forbidden");
    if (!isRequestType(type)) throw new Error("unknown request type");
    const body = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {};
    return analyzer!.request(type, body as Record<string, unknown>);
  });

  createWindow();
});

app.on("web-contents-created", (_e, contents) => {
  contents.on("will-attach-webview", (e) => e.preventDefault());
});

app.on("window-all-closed", () => {
  analyzer?.stop();
  app.quit();
});
