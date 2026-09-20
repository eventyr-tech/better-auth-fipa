import { normalizeCredentialIntegers } from "./credential-store.js";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { deriveDpopJkt } from "@better-auth/core/oauth2";
import { createAuthEndpoint } from "better-auth/api";
import { getTestInstance } from "./fixtures/auth-instance.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { decodeBase64Strict } from "./encoding/base64.js";
import { createDeviceAttestation } from "./plugin.js";
import type {
  DeviceAttestationProvider,
  StoredAttestationCredential,
} from "./types.js";
import {
  createNativeAdmissionChallenge,
  verifyNativeAdmission,
  consumeNativeAdmission,
  type NativeApplicationPolicy,
} from "./first-party/admission.js";
import type { NativeAdmissionBinding } from "./first-party/admission-binding.js";

const APP = "TEAM.admission.test";
const KEY = Buffer.alloc(32, 41).toString("base64");
// Isolated deterministic provider: it verifies the supplied client-data hash,
// not platform hardware. Hardware acceptance remains a separate release gate.
const provider: DeviceAttestationProvider = {
  id: "admission-test",
  maxEvidenceBytes: 1024,
  decodeKeyId: (value) =>
    decodeBase64Strict(value, {
      label: "key_id",
      exactBytes: 32,
      maxBytes: 32,
    }),
  verifyRegistration: () =>
    Promise.resolve({
      applicationId: APP,
      environment: "production",
      publicKey: Buffer.from("test-key").toString("base64"),
      counter: 0,
      extensionsPresent: true,
    }),
  verifyAssertion: ({ credential, clientDataHash, evidence }) => {
    if (!Buffer.from(evidence).equals(Buffer.from(clientDataHash)))
      return Promise.reject(new Error("invalid fixture evidence"));
    return Promise.resolve({
      counter: credential.counter + 1,
      extensionsPresent: true,
    });
  },
};
async function fixture(testWith: "sqlite" | "postgres") {
  const composition = createDeviceAttestation({
    providers: [provider],
    purposes: {
      credentialRegistration: {},
      oauthAuthorization: {
        requireDpopJkt: true,
        protectedClientIds: ["mobile"],
      },
    },
  });
  const operations = new Map<
    string,
    (ctx: GenericEndpointContext) => Promise<unknown>
  >();
  const { auth } = await getTestInstance(
    {
      plugins: [
        composition.serverPlugin,
        {
          id: "admission-probe",
          schema: {
            admissionProbe: {
              fields: {
                credentialId: { type: "string", required: true },
                bindingHash: { type: "string", required: true },
              },
            },
          },
          endpoints: {
            executeAdmissionProbe: createAuthEndpoint(
              "/test-only/admission-probe",
              { method: "POST", body: z.object({ id: z.string() }) },
              async (ctx) => {
                const operation = operations.get(ctx.body.id);
                if (!operation) throw new Error("Unknown probe");
                return operation(ctx);
              },
            ),
          },
        },
      ],
    },
    { testWith, transaction: true },
  );
  const context = await auth.$context;
  const run = async <T>(
    operation: (ctx: GenericEndpointContext) => Promise<T>,
  ): Promise<T> => {
    const id = randomUUID();
    operations.set(id, operation);
    try {
      return (await auth.api.executeAdmissionProbe({ body: { id } })) as T;
    } finally {
      operations.delete(id);
    }
  };
  const registration = await auth.api.createDeviceAttestationChallenge({
    body: {
      provider: provider.id,
      applicationId: APP,
      keyId: KEY,
      operation: "register",
      purpose: "credential-registration",
    },
  });
  const registered = await auth.api.verifyDeviceAttestation({
    body: {
      challengeToken: registration.challengeToken,
      keyId: KEY,
      evidence: Buffer.from("registration").toString("base64"),
    },
  });
  if (!("credentialId" in registered)) throw new Error("Missing credential");
  const credentialId = registered.credentialId;
  const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = key.publicKey.export({ format: "jwk" });
  const policy: NativeApplicationPolicy = {
    clientId: "mobile",
    provider,
    applicationId: APP,
    environment: "production",
    scopes: ["openid", "offline_access"],
    resources: ["https://api.example"],
  };
  const binding: NativeAdmissionBinding = {
    profile: "device-attestation-fipa-v1",
    mode: "native",
    issuer: context.baseURL,
    clientId: "mobile",
    provider: provider.id,
    applicationId: APP,
    environment: "production",
    attemptId: "a".repeat(22),
    codeChallenge: createHash("sha256")
      .update("v".repeat(43))
      .digest("base64url"),
    codeChallengeMethod: "S256",
    dpopJkt: await deriveDpopJkt(jwk),
    scopes: ["openid", "offline_access"],
    resources: ["https://api.example"],
  };
  const challengeEndpointUrl = `${context.baseURL}/first-party/authorization-challenge`;
  const headers = () => {
    const encode = (data: unknown) =>
      Buffer.from(JSON.stringify(data)).toString("base64url");
    const unsigned = `${encode({ alg: "ES256", typ: "dpop+jwt", jwk })}.${encode({ htm: "POST", htu: challengeEndpointUrl, iat: Math.floor(Date.now() / 1000), jti: randomUUID() })}`;
    return new Headers({
      dpop: `${unsigned}.${sign("sha256", Buffer.from(unsigned), { key: key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`,
    });
  };
  const challenge = (change: Partial<NativeAdmissionBinding> = {}) =>
    run((ctx) =>
      createNativeAdmissionChallenge(ctx, policy, {
        binding: { ...binding, ...change },
        keyId: KEY,
      }),
    );
  const verify = (
    prepared: Awaited<ReturnType<typeof challenge>>,
    keyId = KEY,
  ) =>
    run((ctx) =>
      verifyNativeAdmission(ctx, policy, {
        challengeToken: prepared.challengeToken,
        keyId,
        evidence: createHash("sha256")
          .update(Buffer.from(prepared.clientData, "base64url"))
          .digest("base64"),
      }),
    );
  const grant = async () => verify(await challenge());
  const consume = (
    grantToken: string,
    change: Partial<NativeAdmissionBinding> = {},
    fail = false,
    proofHeaders = headers(),
  ) =>
    run((ctx) =>
      consumeNativeAdmission(
        ctx,
        policy,
        {
          grantToken,
          binding: { ...binding, ...change },
          headers: proofHeaders,
          challengeEndpointUrl,
        },
        async (transactionContext, receipt, credential) => {
          await transactionContext.context.adapter.create({
            model: "admissionProbe",
            data: {
              credentialId: credential.id,
              bindingHash: receipt.bindingHash,
            },
          });
          if (fail) throw new Error("injected-continuation-failure");
          return { receipt, credential };
        },
      ),
    );
  const legacyBinding = {
    clientId: "mobile",
    redirectUri: "app://callback",
    codeChallenge: binding.codeChallenge,
    codeChallengeMethod: "S256" as const,
    dpopJkt: binding.dpopJkt,
    scope: "openid offline_access",
  };
  const legacyGrant = async () => {
    const prepared = await auth.api.createDeviceAttestationChallenge({
      body: {
        provider: provider.id,
        applicationId: APP,
        keyId: KEY,
        operation: "assert",
        purpose: "oauth-authorization",
        binding: legacyBinding,
      },
    });
    const result = await auth.api.verifyDeviceAttestation({
      body: {
        challengeToken: prepared.challengeToken,
        keyId: KEY,
        evidence: createHash("sha256")
          .update(Buffer.from(prepared.clientData, "base64url"))
          .digest("base64"),
      },
    });
    if (!("grantToken" in result)) throw new Error("Missing legacy grant");
    return result.grantToken;
  };
  const consumeLegacy = (grantToken: string) =>
    composition.consumeOAuthAuthorizationGrant({
      grantToken,
      userId: "unused",
      binding: legacyBinding,
    });
  const expire = async (kind: "challenge" | "grant") => {
    const values = await context.adapter.findMany<{
      id: string;
      identifier: string;
    }>({ model: "verification" });
    for (const value of values.filter((row) =>
      row.identifier.startsWith(`first-party:admission:${kind}:`),
    )) {
      await context.adapter.update({
        model: "verification",
        where: [{ field: "id", value: value.id }],
        update: { expiresAt: new Date(0) },
      });
    }
  };
  const probes = () => context.adapter.findMany({ model: "admissionProbe" });
  return {
    auth,
    legacyGrant,
    consumeLegacy,
    expire,
    context,
    run,
    credentialId,
    policy,
    binding,
    headers,
    challenge,
    verify,
    grant,
    consume,
    probes,
  };
}

for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "sqlite"
      ? process.env.TEST_POSTGRES !== "true" &&
          Number(process.versions.node.split(".")[0]) >= 22
      : process.env.TEST_POSTGRES === "true",
  )(`Native admission (${database})`, () => {
    it("reuses registration but separates native assertion bytes and atomically consumes admission", async () => {
      const f = await fixture(database);
      const prepared = await f.challenge();
      const encoded: unknown = JSON.parse(
        Buffer.from(prepared.clientData, "base64url").toString("utf8"),
      );
      expect(encoded).toBeInstanceOf(Array);
      expect(
        Buffer.from(prepared.clientData, "base64url").toString("utf8"),
      ).toContain("first-party-admission-challenge/v1");
      const accepted = await f.verify(prepared);
      await expect(f.verify(prepared)).rejects.toThrow();
      const result = await f.consume(accepted.grantToken);
      expect(result.receipt).toMatchObject({
        purpose: "first-party-admission",
        credentialId: f.credentialId,
        binding: { ...f.binding, scopes: [...f.binding.scopes].sort() },
      });
      const appleRow =
        await f.context.adapter.findOne<StoredAttestationCredential>({
          model: "deviceAttestationCredential",
          where: [{ field: "id", value: result.credential.id }],
        });
      expect(normalizeCredentialIntegers(appleRow!).counter).toBe(1);
      await expect(f.consume(accepted.grantToken)).rejects.toThrow();
      expect(await f.probes()).toHaveLength(1);
    });
    it("never treats a legacy grant as native admission or a native grant as legacy authorization", async () => {
      const f = await fixture(database);
      await expect(f.consume(await f.legacyGrant())).rejects.toThrow();
      const { grantToken } = await f.grant();
      await expect(f.consumeLegacy(grantToken)).rejects.toThrow();
      await expect(f.consume(grantToken)).resolves.toHaveProperty("receipt");
      expect(await f.probes()).toHaveLength(1);
    });

    it("rejects expired challenges and grants", async () => {
      const f = await fixture(database);
      const prepared = await f.challenge();
      await f.expire("challenge");
      await expect(f.verify(prepared)).rejects.toThrow();
      const { grantToken } = await f.grant();
      await f.expire("grant");
      await expect(f.consume(grantToken)).rejects.toThrow();
      expect(await f.probes()).toEqual([]);
    });

    it("rejects policy substitutions before provider work", async () => {
      const f = await fixture(database);
      for (const change of [
        { issuer: "https://other.example" },
        { clientId: "other" },
        { applicationId: "OTHER.app" },
        { provider: "other" },
        { environment: "development" as const },
        { scopes: ["admin"] },
        { resources: ["https://other.example"] },
      ]) {
        await expect(f.challenge(change)).rejects.toThrow();
      }
      expect(await f.probes()).toEqual([]);
    });
    it("rejects wrong assertion keys and evidence", async () => {
      const f = await fixture(database);
      const prepared = await f.challenge();
      await expect(
        f.verify(prepared, Buffer.alloc(32, 42).toString("base64")),
      ).rejects.toThrow();
      const another = await f.challenge();
      await expect(
        f.run((ctx) =>
          verifyNativeAdmission(ctx, f.policy, {
            challengeToken: another.challengeToken,
            keyId: KEY,
            evidence: Buffer.from("invalid").toString("base64"),
          }),
        ),
      ).rejects.toThrow("invalid fixture evidence");
      expect(await f.probes()).toEqual([]);
    });
    it("rejects substituted transaction fields and missing proof without consuming valid admission", async () => {
      const f = await fixture(database);
      const { grantToken } = await f.grant();
      await expect(
        f.consume(grantToken, {}, false, new Headers()),
      ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
      for (const change of [
        { attemptId: "b".repeat(22) },
        { codeChallenge: "c".repeat(43) },
        { scopes: ["openid"] },
        { nonce: "injected" },
      ]) {
        await expect(f.consume(grantToken, change)).rejects.toThrow();
      }
      await expect(f.consume(grantToken)).resolves.toHaveProperty("receipt");
      expect(await f.probes()).toHaveLength(1);
    });
    it("rolls admission back with continuation persistence but never restores used proofs", async () => {
      const f = await fixture(database);
      const { grantToken } = await f.grant();
      const headers = f.headers();
      await expect(f.consume(grantToken, {}, true, headers)).rejects.toThrow(
        "injected-continuation-failure",
      );
      expect(await f.probes()).toEqual([]);
      await expect(
        f.consume(grantToken, {}, false, headers),
      ).rejects.toMatchObject({ code: "invalid_dpop_proof" });
      await expect(f.consume(grantToken)).resolves.toHaveProperty("receipt");
    });
    it("allows one consumer across concurrent requests", async () => {
      const f = await fixture(database);
      const { grantToken } = await f.grant();
      const results = await Promise.allSettled([
        f.consume(grantToken),
        f.consume(grantToken),
      ]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      expect(await f.probes()).toHaveLength(1);
    });
    it("rejects changed ownership versions and revoked credentials after verification", async () => {
      const f = await fixture(database);
      const first = await f.grant();
      await f.context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: f.credentialId }],
        update: { bindingVersion: 1 },
      });
      await expect(f.consume(first.grantToken)).rejects.toThrow();
      const next = await f.grant();
      await f.context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: f.credentialId }],
        update: { status: "revoked" },
      });
      await expect(f.consume(next.grantToken)).rejects.toThrow();
      await expect(f.challenge()).rejects.toThrow();
    });
    it("does not admit an exhausted provider key", async () => {
      const f = await fixture(database);
      await f.context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: f.credentialId }],
        update: { counter: 0xffff_fffe },
      });
      await expect(f.verify(await f.challenge())).rejects.toThrow();
      const credential =
        await f.context.adapter.findOne<StoredAttestationCredential>({
          model: "deviceAttestationCredential",
          where: [{ field: "id", value: f.credentialId }],
        });
      expect(credential?.status).toBe("revoked");
    });
  });
}
