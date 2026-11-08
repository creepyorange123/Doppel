// Sandboxed preload: exposes a narrow API, never ipcRenderer itself.
import { contextBridge, ipcRenderer, type IpcRendererEvent } from "electron";

contextBridge.exposeInMainWorld("shadow", {
  request: (type: string, payload: Record<string, unknown> = {}) =>
    ipcRenderer.invoke("shadow:request", type, payload),
  recorder: (action: string) => ipcRenderer.invoke("shadow:recorder", action),
  saveFile: (filename: string, content: string) => ipcRenderer.invoke("shadow:save", filename, content),
  audit: (action: string, payload: Record<string, unknown> = {}) => ipcRenderer.invoke("shadow:audit", action, payload),
  onEvent: (listener: (event: unknown) => void) => {
    const wrapped = (_e: IpcRendererEvent, event: unknown) => listener(event);
    ipcRenderer.on("shadow:event", wrapped);
    return () => ipcRenderer.removeListener("shadow:event", wrapped);
  },
});
