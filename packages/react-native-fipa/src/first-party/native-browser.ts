import type { Spec } from "../NativeFirstPartyTransport.ts";
import type { FirstPartyClientPorts } from "./client.ts";
import { FirstPartyClientError } from "./errors.ts";

/** Browser state/callback validation belongs to the SDK; native owns the system UI. */
export function createNativeBrowser(
  native: Pick<Spec, "randomToken" | "openBrowser" | "cancelBrowser">,
  allowInsecureLoopback = false,
): NonNullable<FirstPartyClientPorts["browser"]> {
  return {
    open: async (input) => {
      if (input.signal.aborted) throw new FirstPartyClientError("cancelled");
      let id: string;
      try {
        id = await native.randomToken();
      } catch {
        throw new FirstPartyClientError("browser_unavailable");
      }
      if (!/^[A-Za-z0-9_-]{43}$/.test(id))
        throw new FirstPartyClientError("browser_unavailable");
      if (input.signal.aborted) throw new FirstPartyClientError("cancelled");
      let abort!: () => void;
      const cancelled = new Promise<never>((_, reject) => {
        abort = () => {
          void native.cancelBrowser(id).catch(() => undefined);
          reject(new FirstPartyClientError("cancelled"));
        };
      });
      input.signal.addEventListener("abort", abort, { once: true });
      try {
        const callback = await Promise.race([
          cancelled,
          native.openBrowser(
            id,
            input.url,
            input.redirectUri,
            input.timeoutMilliseconds,
            allowInsecureLoopback,
          ),
        ]);
        if (input.signal.aborted) throw new FirstPartyClientError("cancelled");
        if (typeof callback !== "string" || callback.length > 32768)
          throw new FirstPartyClientError("invalid_response");
        return callback;
      } catch (error) {
        if (error instanceof FirstPartyClientError) throw error;
        const code =
          error && typeof error === "object" && "code" in error
            ? error.code
            : null;
        if (code === "browser_cancelled")
          throw new FirstPartyClientError("cancelled");
        if (code === "browser_busy")
          throw new FirstPartyClientError("browser_busy");
        if (code === "browser_unavailable")
          throw new FirstPartyClientError("browser_unavailable");
        throw new FirstPartyClientError("browser_failed");
      } finally {
        input.signal.removeEventListener("abort", abort);
      }
    },
  };
}
