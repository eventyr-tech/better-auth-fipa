import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createExampleServer } from "./app.js";

const baseURL = process.env.EXAMPLE_BASE_URL ?? "http://localhost:3000";
const platform = process.env.EXAMPLE_PLATFORM ?? "ios";
if (platform !== "ios" && platform !== "android")
  throw new Error("Invalid EXAMPLE_PLATFORM.");
const android =
  platform === "android"
    ? await (async () => {
        if (!process.env.ANDROID_POLICY_FILE)
          throw new Error(
            "Set ANDROID_POLICY_FILE to the Android test application's policy JSON.",
          );
        const { loadAndroidExampleOptions } =
          await import("./android-config.js");
        return loadAndroidExampleOptions(process.env.ANDROID_POLICY_FILE);
      })()
    : undefined;
const applicationId =
  android?.key.packageName ?? process.env.APP_ATTEST_APPLICATION_ID;
if (!applicationId)
  throw new Error(
    "Set APP_ATTEST_APPLICATION_ID to your signed example app's Team ID and bundle ID.",
  );
const environment = android
  ? "production"
  : (process.env.APP_ATTEST_ENVIRONMENT ?? "development");
if (environment !== "development" && environment !== "production")
  throw new Error("Invalid APP_ATTEST_ENVIRONMENT.");
const secret = process.env.EXAMPLE_AUTH_SECRET;
if (!secret || secret.length < 32)
  throw new Error(
    "Set a persistent EXAMPLE_AUTH_SECRET of at least 32 characters.",
  );
const email = process.env.EXAMPLE_ACCOUNT_EMAIL;
const password = process.env.EXAMPLE_ACCOUNT_PASSWORD;
if (!!email !== !!password)
  throw new Error(
    "Set both EXAMPLE_ACCOUNT_EMAIL and EXAMPLE_ACCOUNT_PASSWORD to bootstrap an account.",
  );
const databasePath = resolve(
  process.env.EXAMPLE_DATABASE_PATH ?? ".data/example.sqlite",
);
mkdirSync(dirname(databasePath), { recursive: true });
const database = new DatabaseSync(databasePath);
const app = await createExampleServer({
  baseURL,
  applicationId,
  environment,
  secret,
  database,
  ...(android ? { android } : {}),
  ...(process.env.EXAMPLE_MFA_CODE_FILE
    ? {
        sendTwoFactorOTP: async (value: { email: string; otp: string }) => {
          writeFileSync(
            process.env.EXAMPLE_MFA_CODE_FILE!,
            JSON.stringify(value),
            { mode: 0o600 },
          );
          await Promise.resolve();
        },
      }
    : {}),
  ...(email && password
    ? { seedAccount: { email, password, name: "Example tester" } }
    : {}),
});

async function handleRequest(
  incoming: IncomingMessage,
  outgoing: ServerResponse,
) {
  try {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of incoming) {
      const bytes = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk as string);
      size += bytes.byteLength;
      if (size > 192 * 1024) {
        outgoing.writeHead(413).end();
        return;
      }
      chunks.push(bytes);
    }
    const method = incoming.method ?? "GET";
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (typeof value === "string") headers.set(name, value);
      else if (Array.isArray(value))
        for (const item of value) headers.append(name, item);
    }
    const response = await app.handler(
      new Request(new URL(incoming.url ?? "/", baseURL), {
        method,
        headers,
        ...(method === "GET" || method === "HEAD"
          ? {}
          : { body: Buffer.concat(chunks) }),
      }),
    );
    const responseHeaders = Object.fromEntries(response.headers);
    delete responseHeaders["set-cookie"];
    outgoing.writeHead(response.status, {
      ...responseHeaders,
      ...(response.headers.getSetCookie().length
        ? { "set-cookie": response.headers.getSetCookie() }
        : {}),
    });
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    outgoing.writeHead(500).end("Example request failed.");
  }
}

const server = createServer((incoming, outgoing) => {
  void handleRequest(incoming, outgoing);
}).listen(
  Number(process.env.EXAMPLE_PORT ?? (new URL(baseURL).port || 3000)),
  "0.0.0.0",
  () => {
    console.log(`First-party authentication example listening at ${baseURL}`);
  },
);
for (const signal of ["SIGINT", "SIGTERM"] as const)
  process.once(signal, () =>
    server.close(() => {
      database.close();
      process.exit(0);
    }),
  );
