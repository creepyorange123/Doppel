import { describe, expect, it } from "vitest";
import { bundleRoot, parseStart } from "./audit";

const slack = { path: "/Applications/Slack.app", name: "Slack" };

describe("parseStart", () => {
  it("accepts a normal audit", () => {
    expect(parseStart({ apps: [slack], minutes: 30, label: " Work " })).toEqual({
      apps: [{ ...slack, capture: "full" }],
      minutes: 30,
      label: "Work",
    });
    expect(parseStart({ apps: [{ ...slack, capture: "metadata_only" }], minutes: 15 })).toMatchObject({
      apps: [{ capture: "metadata_only" }],
    });
  });

  it("rejects bad input from the renderer", () => {
    expect(parseStart({ apps: [], minutes: 30 })).toMatch(/pick 1/);
    expect(parseStart({ apps: Array(21).fill(slack), minutes: 30 })).toMatch(/pick 1/);
    expect(parseStart({ apps: [slack], minutes: 0 })).toMatch(/duration/);
    expect(parseStart({ apps: [slack], minutes: 241 })).toMatch(/duration/);
    expect(parseStart({ apps: [slack], minutes: 1.5 })).toMatch(/duration/);
    expect(parseStart({ apps: [{ path: "Slack.app", name: "Slack" }], minutes: 5 })).toBe("bad app");
    // A comma would add another entry to the recorder's process filter.
    expect(parseStart({ apps: [{ path: "/Applications/A.app,/usr/bin", name: "A" }], minutes: 5 })).toBe("bad app");
    expect(parseStart({ apps: [{ path: "/Applications/A.app", name: "A\nB" }], minutes: 5 })).toBe("bad app");
    // The renderer can't pick processes by id: extra fields are dropped.
    expect(parseStart({ apps: [{ ...slack, pids: [1] }], minutes: 5 })).toEqual({ apps: [{ ...slack, capture: "full" }], minutes: 5 });
    expect(parseStart(null)).toBe("bad payload");
  });
});

describe("bundleRoot", () => {
  it("finds the .app bundle of an executable", () => {
    expect(bundleRoot("/x/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron")).toBe(
      "/x/node_modules/electron/dist/Electron.app",
    );
    expect(bundleRoot("/usr/local/bin/electron")).toBe("/usr/local/bin/electron");
  });
});
