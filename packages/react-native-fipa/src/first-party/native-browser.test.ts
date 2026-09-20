import { describe, expect, it, vi } from "vitest";
import { createNativeBrowser } from "./native-browser.ts";

function fixture() {
  const native = {
    randomToken: vi.fn().mockResolvedValue("i".repeat(43)),
    openBrowser: vi.fn().mockResolvedValue("example:/callback?code=code"),
    cancelBrowser: vi.fn().mockResolvedValue(undefined),
  };
  const controller = new AbortController();
  const input = {
    url: "https://issuer.example/auth/oauth2/authorize?client_id=mobile&request_uri=opaque",
    redirectUri: "example:/callback",
    timeoutMilliseconds: 60000,
    signal: controller.signal,
  };
  return { native, controller, input, browser: createNativeBrowser(native) };
}
describe("native external browser", () => {
  it("delegates to the system browser with cancellation and a bounded duration", async () => {
    const f = fixture();
    await expect(f.browser.open(f.input)).resolves.toBe(
      "example:/callback?code=code",
    );
    expect(f.native.openBrowser).toHaveBeenCalledWith(
      "i".repeat(43),
      f.input.url,
      f.input.redirectUri,
      60000,
      false,
    );
    f.controller.abort();
    expect(f.native.cancelBrowser).not.toHaveBeenCalled();
  });
  it("does not open an already cancelled browser", async () => {
    const f = fixture();
    f.controller.abort();
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(f.native.openBrowser).not.toHaveBeenCalled();
  });
  it("checks cancellation after request ID creation", async () => {
    const f = fixture();
    f.native.randomToken.mockImplementation(() => {
      f.controller.abort();
      return Promise.resolve("i".repeat(43));
    });
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(f.native.openBrowser).not.toHaveBeenCalled();
  });
  it("finishes cancellation even if native completion never arrives", async () => {
    const f = fixture();
    f.native.openBrowser.mockImplementation(() => {
      f.controller.abort();
      return new Promise<never>(() => undefined);
    });
    f.native.cancelBrowser.mockRejectedValue(new Error("native details"));
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(f.native.cancelBrowser).toHaveBeenCalledWith("i".repeat(43));
  });
  it.each([
    ["browser_cancelled", "cancelled"],
    ["browser_busy", "browser_busy"],
    ["browser_unavailable", "browser_unavailable"],
    ["other", "browser_failed"],
  ])("redacts native error %s", async (code, expected) => {
    const f = fixture();
    f.native.openBrowser.mockRejectedValue({
      code,
      message: "secret callback code",
    });
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: expected,
      message: "The authentication operation could not be completed.",
    });
  });
  it("rejects malformed IDs and callbacks without leaking native details", async () => {
    const f = fixture();
    f.native.randomToken.mockRejectedValue(new Error("secret"));
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: "browser_unavailable",
    });
    f.native.randomToken.mockResolvedValue("bad-id");
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: "browser_unavailable",
    });
    f.native.randomToken.mockResolvedValue("i".repeat(43));
    f.native.openBrowser.mockResolvedValue("x".repeat(32769));
    await expect(f.browser.open(f.input)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
});
