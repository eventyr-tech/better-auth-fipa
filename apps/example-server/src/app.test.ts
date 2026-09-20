import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from "jose";
import { expect, it } from "vitest";
import type { DeviceAttestationProvider } from "@eventyr-tech/better-auth-fipa";
import {
  createExampleServer,
  EXAMPLE_CALLBACK,
  EXAMPLE_CLIENT_ID,
  EXAMPLE_SCOPES,
} from "./app.js";

const origin = "http://localhost:3000";
const issuer = `${origin}/api/auth`;
const applicationId = "TEAM.example";
const keyId = Buffer.alloc(32, 7).toString("base64");
const seedAccount = {
  email: "tester@example.test",
  password: "example-password-for-tests",
  name: "Tester",
};
const hash = (value: string | Buffer) =>
  createHash("sha256").update(value).digest();
// Only Apple's platform evidence is synthetic. Database, password, PKCE,
// DPoP, public package entry points and provider issuance are real.
const provider: DeviceAttestationProvider = {
  id: "app-attest",
  maxEvidenceBytes: 1024,
  decodeKeyId: (value) => Buffer.from(value, "base64"),
  verifyRegistration: () =>
    Promise.resolve({
      applicationId,
      environment: "development",
      publicKey: "fixture-key",
      counter: 0,
      extensionsPresent: false,
    }),
  verifyAssertion: ({ credential, clientDataHash, evidence }) => {
    if (!Buffer.from(evidence).equals(Buffer.from(clientDataHash)))
      throw new Error("Invalid fixture evidence");
    return Promise.resolve({
      counter: credential.counter + 1,
      extensionsPresent: false,
    });
  },
};
interface Wire {
  auth_session: string;
  authorization_code: string;
  step: { id: string; kind: string };
}
interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  first_party_account: { sub: string; credential_id: string };
}

it.each(["password", "email-otp"] as const)(
  "runs native %s login, durable restart/refresh, DPoP access, logout and retirement through the public composition",
  async (method) => {
    const temporary = mkdtempSync(join(tmpdir(), "attestation-example-test-"));
    const path = join(temporary, "example.sqlite");
    let database = new DatabaseSync(path);
    const emails: { email: string; otp: string }[] = [];
    const setup = () =>
      createExampleServer({
        baseURL: origin,
        applicationId,
        environment: "development",
        secret: "example-test-secret-at-least-32-characters",
        database,
        seedAccount,
        provider,
        ...(method === "email-otp"
          ? {
              sendEmailOTP: (value: { email: string; otp: string }) => {
                emails.push(value);
                return Promise.resolve();
              },
            }
          : {}),
      });
    try {
      let app = await setup();
      const key = await generateKeyPair("ES256");
      const jwk = await exportJWK(key.publicKey);
      const dpopJkt = await calculateJwkThumbprint(jwk);
      const proof = (path: string, method = "POST", token?: string) =>
        new SignJWT({
          htu: `${issuer}${path}`,
          htm: method,
          ...(token ? { ath: hash(token).toString("base64url") } : {}),
        })
          .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(key.privateKey);
      const json = (path: string, body: unknown) =>
        app.handler(
          new Request(`${issuer}${path}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          }),
        );
      const form = async (
        path: string,
        body: Record<string, string>,
        dpop?: string | null,
      ) => {
        const header = dpop === undefined ? await proof(path) : dpop;
        return app.handler(
          new Request(`${issuer}${path}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              ...(header ? { DPoP: header } : {}),
            },
            body: new URLSearchParams(body),
          }),
        );
      };
      const registration = await json("/device-attestation/challenge", {
        provider: "app-attest",
        applicationId,
        keyId,
        operation: "register",
        purpose: "credential-registration",
      });
      expect(registration.status).toBe(200);
      const challenge = (await registration.json()) as {
        challengeToken: string;
      };
      expect(
        (
          await json("/device-attestation/verify", {
            challengeToken: challenge.challengeToken,
            keyId,
            evidence: "YQ==",
          })
        ).status,
      ).toBe(200);

      async function login(useOTP = method === "email-otp") {
        const verifier = randomBytes(32).toString("base64url");
        const binding = {
          profile: "device-attestation-fipa-v1",
          mode: "native",
          issuer,
          clientId: EXAMPLE_CLIENT_ID,
          provider: "app-attest",
          applicationId,
          environment: "development",
          attemptId: randomBytes(32).toString("base64url"),
          codeChallenge: hash(verifier).toString("base64url"),
          codeChallengeMethod: "S256",
          dpopJkt,
          scopes: EXAMPLE_SCOPES,
          resources: [],
        };
        const prepared = await json("/first-party/attestation/challenge", {
          binding,
          keyId,
        });
        expect(prepared.status).toBe(200);
        const preparation = (await prepared.json()) as {
          challengeToken: string;
          clientData: string;
        };
        const verified = await json("/first-party/attestation/verify", {
          clientId: EXAMPLE_CLIENT_ID,
          challengeToken: preparation.challengeToken,
          keyId,
          evidence: hash(
            Buffer.from(preparation.clientData, "base64url"),
          ).toString("base64"),
        });
        expect(verified.status).toBe(200);
        const grant = (await verified.json()) as { grantToken: string };
        const base = { profile: binding.profile, client_id: EXAMPLE_CLIENT_ID };
        const initial = {
          ...base,
          response_type: "code",
          scope: EXAMPLE_SCOPES.join(" "),
          code_challenge: binding.codeChallenge,
          code_challenge_method: "S256",
          authorization_attempt: binding.attemptId,
          device_attestation: grant.grantToken,
        };
        expect(
          (await form("/first-party/authorization-challenge", initial, null))
            .status,
        ).toBe(400);
        const started = await form(
          "/first-party/authorization-challenge",
          initial,
        );
        expect(started.status).toBe(403);
        let step = (await started.json()) as Wire;
        expect(step.step.kind).toBe(
          method === "email-otp" ? "authentication" : "password",
        );
        if (useOTP) {
          const deliveredBefore = emails.length;
          const requested = await form("/first-party/authorization-challenge", {
            ...base,
            auth_session: step.auth_session,
            step_id: step.step.id,
            response: JSON.stringify({
              kind: "email-otp-request",
              email: seedAccount.email,
            }),
          });
          expect(requested.status).toBe(403);
          step = (await requested.json()) as Wire;
          expect(step).not.toHaveProperty("failure");
          expect(emails).toHaveLength(deliveredBefore + 1);
          expect(step.step.kind).toBe("email-otp");
          expect(emails.at(-1)?.email).toBe(seedAccount.email);
        }
        const authorized = await form("/first-party/authorization-challenge", {
          ...base,
          auth_session: step.auth_session,
          step_id: step.step.id,
          response: JSON.stringify(
            useOTP
              ? { kind: "email-otp", otp: emails.at(-1)!.otp }
              : {
                  kind: "password",
                  email: seedAccount.email,
                  password: seedAccount.password,
                },
          ),
        });
        const outcome = (await authorized.json()) as Wire & {
          error?: string;
          failure?: string;
        };
        expect(
          authorized.status,
          JSON.stringify({
            error: outcome.error,
            failure: outcome.failure,
            step: outcome.step?.kind,
          }),
        ).toBe(200);
        const code = outcome;
        const redeemed = await form("/oauth2/token", {
          client_id: EXAMPLE_CLIENT_ID,
          grant_type: "authorization_code",
          code: code.authorization_code,
          code_verifier: verifier,
        });
        expect(redeemed.status).toBe(200);
        const tokens = (await redeemed.json()) as Tokens;
        expect(tokens.token_type).toBe("DPoP");
        expect(tokens.first_party_account.sub).toEqual(expect.any(String));
        return tokens;
      }
      const access = async (token: string, dpop?: string) =>
        app.handler(
          new Request(`${issuer}/example/account`, {
            headers: {
              Authorization: `DPoP ${token}`,
              DPoP: dpop ?? (await proof("/example/account", "GET", token)),
            },
          }),
        );
      const tokens = await login();
      const once = await proof("/example/account", "GET", tokens.access_token);
      const resource = await access(tokens.access_token, once);
      expect(resource.status).toBe(200);
      expect(await resource.json()).toMatchObject({
        subject: tokens.first_party_account.sub,
        credentialId: tokens.first_party_account.credential_id,
      });
      expect((await access(tokens.access_token, once)).status).toBe(401);
      expect(
        (
          await app.handler(
            new Request(`${issuer}/example/account`, {
              headers: { Authorization: `Bearer ${tokens.access_token}` },
            }),
          )
        ).status,
      ).toBe(401);

      database.close();
      database = new DatabaseSync(path);
      app = await setup();
      const refreshed = await form("/oauth2/token", {
        client_id: EXAMPLE_CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
      });
      expect(refreshed.status).toBe(200);
      const rotated = (await refreshed.json()) as Tokens;
      expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
      expect(rotated.first_party_account).toEqual(tokens.first_party_account);
      expect((await access(rotated.access_token)).status).toBe(200);
      const terminate = async (action: "logout" | "retire", token: string) =>
        app.handler(
          new Request(`${issuer}/first-party/${action}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `DPoP ${token}`,
              DPoP: await proof(`/first-party/${action}`, "POST", token),
            },
            body: "{}",
          }),
        );
      expect((await terminate("logout", rotated.access_token)).status).toBe(
        200,
      );
      expect((await access(rotated.access_token)).status).toBe(401);
      const accounts = database
        .prepare('SELECT "userId", "accountId", "providerId" FROM "account"')
        .all();
      if (method === "email-otp") {
        // BA intentionally strips unproven password links when OTP establishes
        // mailbox ownership. Do not restore that password to make this pass.
        expect(accounts).toEqual([]);
        // Simulate the resend cooldown elapsing; retain its charged window count.
        database
          .prepare('UPDATE "firstPartyEmailBudget" SET "nextRequestAt" = ?')
          .run(new Date(0).toISOString());
      } else
        expect(accounts).toEqual([
          expect.objectContaining({
            userId: tokens.first_party_account.sub,
            accountId: tokens.first_party_account.sub,
            providerId: "credential",
          }),
        ]);
      const second = await login();
      expect(second.first_party_account).toEqual(tokens.first_party_account);
      expect((await terminate("retire", second.access_token)).status).toBe(200);
      expect((await access(second.access_token)).status).toBe(401);
      expect(
        (
          await form("/oauth2/token", {
            client_id: EXAMPLE_CLIENT_ID,
            grant_type: "refresh_token",
            refresh_token: second.refresh_token,
          })
        ).status,
      ).toBe(400);

      // The reference composition does not enable legacy JSON or ordinary OAuth issuance.
      expect(
        (
          await json("/first-party/authorization-challenge", {
            client_id: EXAMPLE_CLIENT_ID,
          })
        ).status,
      ).toBe(415);
      const ordinary = new URL(`${issuer}/oauth2/authorize`);
      ordinary.search = new URLSearchParams({
        client_id: EXAMPLE_CLIENT_ID,
        response_type: "code",
        redirect_uri: EXAMPLE_CALLBACK,
      }).toString();
      expect((await app.handler(new Request(ordinary))).status).toBe(400);
      expect(
        (
          await json("/sign-up/email", {
            ...seedAccount,
            email: "other@example.test",
          })
        ).ok,
      ).toBe(false);
      const page = await app.handler(
        new Request(`${origin}/login?callbackURL=https://untrusted.example`),
      );
      expect(page.headers.get("Content-Security-Policy")).toContain(
        "frame-ancestors 'none'",
      );
      expect(await page.text()).not.toContain("untrusted.example");
      expect(
        (await app.handler(new Request("http://wrong.example/login"))).status,
      ).toBe(400);
      expect((await app.handler(new Request(`${origin}/unknown`))).status).toBe(
        404,
      );
    } finally {
      database.close();
      rmSync(temporary, { recursive: true, force: true });
    }
  },
  30_000,
);

it("requires actual browser MFA after enrollment and rejects an incorrect code", async () => {
  const database = new DatabaseSync(":memory:");
  let otp = "";
  const app = await createExampleServer({
    baseURL: origin,
    applicationId,
    environment: "development",
    secret: "example-test-secret-at-least-32-characters",
    database,
    seedAccount,
    provider,
    sendTwoFactorOTP: (value) => {
      otp = value.otp;
      return Promise.resolve();
    },
  });
  const cookies = new Map<string, string>();
  const post = async (path: string, body: object) => {
    const response = await app.handler(
      new Request(origin + "/api/auth" + path, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin,
          cookie: [...cookies].map(([k, v]) => k + "=" + v).join("; "),
        },
        body: JSON.stringify(body),
      }),
    );
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";")[0]!;
      const index = pair.indexOf("=");
      cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return response;
  };
  try {
    expect((await post("/sign-in/email", seedAccount)).status).toBe(200);
    expect(
      (await post("/two-factor/enable", { password: seedAccount.password }))
        .status,
    ).toBe(200);
    expect((await post("/two-factor/send-otp", {})).status).toBe(200);
    expect(otp).toMatch(/^\d{6}$/);
    expect((await post("/two-factor/verify-otp", { code: otp })).status).toBe(
      200,
    );
    cookies.clear();
    const login = await post("/sign-in/email", seedAccount);
    expect(login.status).toBe(200);
    expect(await login.json()).toMatchObject({ twoFactorRedirect: true });
    expect((await post("/two-factor/send-otp", {})).status).toBe(200);
    const wrong = otp === "000000" ? "111111" : "000000";
    expect(
      (await post("/two-factor/verify-otp", { code: wrong })).status,
    ).not.toBe(200);
    const verified = await post("/two-factor/verify-otp", { code: otp });
    expect(verified.status).toBe(200);
    expect(await verified.json()).toMatchObject({
      user: { email: seedAccount.email },
    });
    const page = await app.handler(new Request(origin + "/login"));
    expect(await page.text()).toContain("/api/auth/two-factor/verify-otp");
  } finally {
    database.close();
  }
});
