import { describe, expect, it } from "vitest";
import { setTimeout as delay } from "node:timers/promises";
import {
  createDeviceAttestation,
  type DeviceAttestationProvider,
  type StoredAttestationCredential,
} from "./index.js";
import { getTestInstance } from "./fixtures/auth-instance.js";

// Public consumer contracts used by Eventyr in addition to native login.
// These are synthetic test identities, never production attestation evidence.
const applicationId = "TEAM.io.example.consumer";
const keyId = Buffer.alloc(32, 17).toString("base64");
const namespace = "io.eventyr.mobile.device-pairing";
const issuanceBinding = {
  namespace,
  subject: "dedicated-pairing-ceremony",
  dpopJkt: Buffer.alloc(32, 18).toString("base64url"),
};
const provider: DeviceAttestationProvider = {
  id: "consumer-test",
  maxEvidenceBytes: 1024,
  decodeKeyId: (value) => Buffer.from(value, "base64"),
  verifyRegistration: () =>
    Promise.resolve({
      applicationId,
      environment: "production",
      publicKey: "synthetic-public-key",
      counter: 0,
      extensionsPresent: false,
      validationCategory: 0xffff_ffff,
    }),
  verifyAssertion: ({ credential }) =>
    Promise.resolve({
      counter: credential.counter + 1,
      extensionsPresent: false,
      validationCategory: 0xffff_ffff,
    }),
};

for (const database of ["sqlite", "postgres"] as const) {
  describe.runIf(
    database === "postgres"
      ? process.env.TEST_POSTGRES === "true"
      : process.env.TEST_POSTGRES !== "true",
  )(`consumer contracts (${database})`, () => {
    async function fixture() {
      const composition = createDeviceAttestation({
        providers: [provider],
        purposes: {
          credentialRegistration: {},
          oauthAuthorization: {
            protectedClientIds: ["eventyr_mobile"],
            requireDpopJkt: true,
          },
          credentialIssuance: {
            allowedNamespaces: [namespace],
            requireDpopJkt: true,
          },
        },
      });
      const f = await getTestInstance(
        { plugins: [composition.serverPlugin] },
        {
          testWith: database,
          transaction: true,
        },
      );
      const context = await f.auth.$context;
      const challenge = await f.auth.api.createDeviceAttestationChallenge({
        body: {
          provider: provider.id,
          applicationId,
          keyId,
          operation: "register",
          purpose: "credential-registration",
        },
      });
      await f.auth.api.verifyDeviceAttestation({
        body: {
          challengeToken: challenge.challengeToken,
          keyId,
          evidence: Buffer.from("synthetic").toString("base64"),
        },
      });
      const credential = async () => {
        const row = await context.adapter.findOne<StoredAttestationCredential>({
          model: "deviceAttestationCredential",
          where: [{ field: "applicationId", value: applicationId }],
        });
        if (!row) throw new Error("Missing consumer credential");
        return row;
      };
      const assertIssuance = async () => {
        const challenge = await f.auth.api.createDeviceAttestationChallenge({
          body: {
            provider: provider.id,
            applicationId,
            keyId,
            operation: "assert",
            purpose: "credential-issuance",
            binding: issuanceBinding,
          },
        });
        return f.auth.api.verifyDeviceAttestation({
          body: {
            challengeToken: challenge.challengeToken,
            keyId,
            evidence: Buffer.from("synthetic").toString("base64"),
          },
        });
      };
      return { ...f, composition, context, credential, assertIssuance };
    }

    it("preserves the full UInt32 range through generated schema and real adapter reads", async () => {
      const f = await fixture();
      for (const counter of [0x8000_0000, 0xffff_fffe, 0xffff_ffff]) {
        await f.context.adapter.update({
          model: "deviceAttestationCredential",
          where: [{ field: "id", value: (await f.credential()).id }],
          update: { counter: counter - 1 },
        });
        await f.assertIssuance();
        const stored = await f.credential();
        expect(Number(stored.counter)).toBe(counter);
        expect(Number(stored.validationCategory)).toBe(0xffff_ffff);
      }
    });

    it.runIf(database === "postgres")(
      "rechecks guarded state after waiting for another transaction's row lock",
      async () => {
        const f = await fixture();
        if (!f.postgres) throw new Error("Expected PostgreSQL fixture");
        const id = (await f.credential()).id;
        let unlock!: () => void;
        let locked!: () => void;
        const lockHeld = new Promise<void>((resolve) => {
          locked = resolve;
        });
        const release = new Promise<void>((resolve) => {
          unlock = resolve;
        });
        const mutation = {
          model: "deviceAttestationCredential",
          where: [
            { field: "id", value: id },
            { field: "bindingVersion", value: 0 },
          ],
          increment: { bindingVersion: 1 },
        };
        const first = f.context.adapter.transaction(async (tx) => {
          const result = await tx.incrementOne(mutation);
          locked();
          await release;
          return result;
        });
        // Propagate setup errors instead of leaving the lock handshake pending.
        await Promise.race([lockHeld, first]);
        const second = f.context.adapter.incrementOne(mutation);
        try {
          const deadline = Date.now() + 5000;
          let waiting = false;
          do {
            const result = await f.postgres.pool.query<{ waiting: boolean }>(
              "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND application_name = $1) AS waiting",
              [f.postgres.schema],
            );
            waiting = result.rows[0]?.waiting === true;
            if (!waiting) await delay(10);
          } while (!waiting && Date.now() < deadline);
          expect(
            waiting,
            "second update must actually wait on the first transaction",
          ).toBe(true);
        } finally {
          unlock();
          await Promise.allSettled([first, second]);
        }
        expect(await first).not.toBeNull();
        expect(
          await second,
          "stale bindingVersion must not match after lock release",
        ).toBeNull();
        expect(Number((await f.credential()).bindingVersion)).toBe(1);
      },
    );

    it("consumes a host pairing grant once and preserves external binding through cleanup and user deletion", async () => {
      const f = await fixture();
      const grant = await f.assertIssuance();
      if (!("grantToken" in grant)) throw new Error("Expected issuance grant");
      const consume = () =>
        f.composition.consumeCredentialIssuanceGrant({
          grantToken: grant.grantToken,
          binding: issuanceBinding,
        });
      const results = await Promise.allSettled([consume(), consume()]);
      expect(
        results.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      expect(await f.credential()).toMatchObject({
        externallyBound: true,
        userId: null,
        unboundExpiresAt: null,
      });
      // Registration challenge runs opportunistic cleanup. Externally issued
      // credentials must not be treated as abandoned, even after their old TTL.
      await f.context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: (await f.credential()).id }],
        update: { unboundExpiresAt: new Date(0) },
      });
      await f.auth.api.createDeviceAttestationChallenge({
        body: {
          provider: provider.id,
          applicationId,
          keyId: Buffer.alloc(32, 19).toString("base64"),
          operation: "register",
          purpose: "credential-registration",
        },
      });
      expect(await f.credential()).toMatchObject({
        status: "active",
        externallyBound: true,
      });
      const { user } = await f.signInWithTestUser();
      const binding = {
        clientId: "eventyr_mobile",
        redirectUri: "example:/callback",
        codeChallenge: Buffer.alloc(32, 20).toString("base64url"),
        codeChallengeMethod: "S256" as const,
        scope: "offline_access",
        dpopJkt: issuanceBinding.dpopJkt,
      };
      const challenge = await f.auth.api.createDeviceAttestationChallenge({
        body: {
          provider: provider.id,
          applicationId,
          keyId,
          operation: "assert",
          purpose: "oauth-authorization",
          binding,
        },
      });
      const authorization = await f.auth.api.verifyDeviceAttestation({
        body: {
          challengeToken: challenge.challengeToken,
          keyId,
          evidence: Buffer.from("synthetic").toString("base64"),
        },
      });
      if (!("grantToken" in authorization))
        throw new Error("Expected OAuth grant");
      await f.composition.consumeOAuthAuthorizationGrant({
        grantToken: authorization.grantToken,
        binding,
        userId: user.id,
      });
      await f.context.internalAdapter.deleteUser(user.id);
      expect(await f.credential()).toMatchObject({
        status: "revoked",
        externallyBound: true,
        publicKey: null,
      });
    });
  });
}
