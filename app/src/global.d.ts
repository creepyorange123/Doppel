import type { ShadowApi } from "./shared/protocol";

declare global {
  interface Window {
    shadow: ShadowApi;
  }
}
