import { readFile } from "node:fs/promises";
import { GoogleAuth } from "google-auth-library";
import {
  androidHardware,
  type AndroidHardwareOptions,
} from "@eventyr-tech/better-auth-fipa/first-party";

/** Host-only configuration. ADC credentials and access tokens never enter the app. */
export async function loadAndroidExampleOptions(
  path: string,
): Promise<AndroidHardwareOptions> {
  const bytes = await readFile(path);
  if (bytes.length > 65536)
    throw new Error("Android policy file is too large.");
  const value: unknown = JSON.parse(bytes.toString("utf8"));
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !["key", "play", "trust"].includes(key)) ||
    !("key" in value) ||
    !("play" in value) ||
    !value.play ||
    typeof value.play !== "object" ||
    Array.isArray(value.play) ||
    "getAccessToken" in value.play
  )
    throw new Error(
      "Android policy must contain key and play policies, without credentials.",
    );
  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/playintegrity"],
  });
  const options = {
    ...value,
    play: {
      ...value.play,
      async getAccessToken(signal: AbortSignal) {
        signal.throwIfAborted();
        const token = await auth.getAccessToken();
        signal.throwIfAborted();
        if (!token) throw new Error("Google credentials are unavailable.");
        return token;
      },
    },
  } as AndroidHardwareOptions;
  // Validate every policy field before opening/migrating the example database.
  // Construction performs no Google request and has no mock-evidence fallback.
  androidHardware(options);
  return options;
}
