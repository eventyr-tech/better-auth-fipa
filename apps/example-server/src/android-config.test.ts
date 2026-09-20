import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, expect, it, vi } from "vitest";
import {
  createExampleServer,
  EXAMPLE_ANDROID_CLIENT_ID,
  EXAMPLE_CLIENT_ID,
} from "./app.js";

const credential = vi.hoisted(() => ({
  token: vi.fn(() => Promise.resolve("host-only-google-token")),
}));
vi.mock("google-auth-library", () => ({
  GoogleAuth: class {
    getAccessToken = credential.token;
  },
}));
import { loadAndroidExampleOptions } from "./android-config.js";
const policy = {
  key: {
    policyVersion: "device-test-v1",
    packageName: "com.example.deviceattestation",
    signingCertificateSets: [[Buffer.alloc(32, 1).toString("base64url")]],
    minimumVersionCode: "1",
    allowedSecurityLevels: ["tee"],
    minimumOsVersion: 90000,
    minimumOsPatchLevel: 202401,
    requireUnlockedDevice: true,
  },
  play: {
    policyVersion: "device-test-v1",
    packageName: "com.example.deviceattestation",
    signingCertificateSets: [[Buffer.alloc(32, 1).toString("base64url")]],
    minimumVersionCode: "1",
    maxAgeSeconds: 120,
    clockSkewSeconds: 5,
    requireStrongIntegrity: false,
  },
};
const directories: string[] = [];
async function file(value: unknown) {
  const directory = await mkdtemp(join(tmpdir(), "android-example-policy-"));
  directories.push(directory);
  const path = join(directory, "policy.json");
  await writeFile(path, JSON.stringify(value));
  return path;
}
afterEach(async () => {
  credential.token.mockClear();
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
it("validates policy without fetching credentials and honors cancellation before credentials", async () => {
  const options = await loadAndroidExampleOptions(await file(policy));
  expect(credential.token).not.toHaveBeenCalled();
  const signal = AbortSignal.abort();
  await expect(options.play.getAccessToken(signal)).rejects.toBeDefined();
  expect(credential.token).not.toHaveBeenCalled();
  await expect(
    options.play.getAccessToken(new AbortController().signal),
  ).resolves.toBe("host-only-google-token");
  expect(credential.token).toHaveBeenCalledOnce();
});
it.each([
  null,
  { ...policy, credentials: { access_token: "forbidden" } },
  { ...policy, play: { ...policy.play, getAccessToken: "forbidden" } },
  { ...policy, play: { ...policy.play, packageName: "wrong.package" } },
  { ...policy, key: { ...policy.key, allowedSecurityLevels: ["software"] } },
  {
    ...policy,
    play: { ...policy.play, signingCertificateSets: [["invalid"]] },
  },
])(
  "rejects incomplete, weakened or credential-bearing configuration: %j",
  async (value) => {
    await expect(
      loadAndroidExampleOptions(await file(value)),
    ).rejects.toThrow();
    expect(credential.token).not.toHaveBeenCalled();
  },
);
it("runs the real Android key challenge endpoint through the public server composition", async () => {
  const android = await loadAndroidExampleOptions(await file(policy));
  const database = new DatabaseSync(":memory:");
  try {
    const options = {
      baseURL: "http://localhost:3000",
      applicationId: policy.key.packageName,
      environment: "production" as const,
      secret: "example-test-secret-at-least-32-characters",
      database,
      android,
    };
    await expect(
      createExampleServer({ ...options, environment: "development" }),
    ).rejects.toThrow();
    const app = await createExampleServer(options);
    const challenge = (clientId: string) =>
      app.handler(
        new Request(
          `${options.baseURL}/api/auth/first-party/android/key-challenge`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ clientId }),
          },
        ),
      );
    expect((await challenge(EXAMPLE_CLIENT_ID)).status).toBe(400);
    const response = await challenge(EXAMPLE_ANDROID_CLIENT_ID);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.attestationChallenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(body.keyChallengeToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      database.prepare('SELECT "clientId" FROM "oauthClient"').all(),
    ).toEqual([{ clientId: EXAMPLE_ANDROID_CLIENT_ID }]);
    expect(credential.token).not.toHaveBeenCalled();
  } finally {
    database.close();
  }
});
