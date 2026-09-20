import "reflect-metadata";
import { X509Certificate as NodeCertificate } from "node:crypto";
import {
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  X509Certificate,
} from "@peculiar/x509";
import { DeviceAttestationError, rejection } from "../errors.js";
import { sha256 } from "../protocol/crypto.js";
import { createAndroidKeyPolicy, type AndroidKeyPolicy } from "./key-policy.js";

const KEY_DESCRIPTION = "1.3.6.1.4.1.11129.2.1.17";
const PROVISIONING = "1.3.6.1.4.1.11129.2.1.30";
const knownCritical = new Set(["2.5.29.19", "2.5.29.15"]);
/** Trusted server state, never values supplied in the device evidence. The
 * fetching layer must authenticate Google's root/status endpoints and bound
 * cache validity. A missing/stale snapshot is not permission to skip checks. */
export interface AndroidTrustSnapshot {
  version: string;
  fetchedAt: Date;
  expiresAt: Date;
  roots: readonly { spkiSha256: string; allowFactoryExpiry: boolean }[];
  /** All listed serials are denied, including both REVOKED and SUSPENDED. */
  revokedSerials: readonly string[];
}

/** Full native profile combines this key evidence with Play Integrity and
 * live DPoP possession. This internal verifier alone never issues a grant. */
export function createAndroidKeyAttestationVerifier(policy: AndroidKeyPolicy) {
  const checkProperties = createAndroidKeyPolicy(policy);
  return (input: {
    certificateChain: readonly Uint8Array[];
    expectedChallenge: Uint8Array;
    expectedDpopJkt: string;
    trust: AndroidTrustSnapshot;
    now?: Date;
    /** Only from an existing server-verified credential. New enrollment MUST
     * omit this; clients cannot backdate certificate validation. */
    verifiedAtCreation?: Date;
  }) => {
    const now = input.now ?? new Date();
    const path = verifyAndroidCertificatePath(
      input.certificateChain,
      input.trust,
      now,
      input.verifiedAtCreation,
    );
    const properties = checkProperties(path.extension, input.expectedChallenge);
    if (
      path.attestationSecurityLevel &&
      path.attestationSecurityLevel !== properties.attestationSecurityLevel
    )
      throw rejected("android_certificate_security_level_mismatch");
    if (
      typeof input.expectedDpopJkt !== "string" ||
      input.expectedDpopJkt !== path.dpopJkt
    )
      throw rejected("android_attested_key_mismatch");
    return {
      provider: "android-key-attestation" as const,
      kind: "credential-key" as const,
      properties,
      dpopJkt: path.dpopJkt,
      publicKeySpki: path.publicKeySpki,
      verifiedAt: new Date(now),
      trustVersion: input.trust.version,
      provisioning: path.provisioning,
      certificateSerials: path.certificateSerials,
      rootSpkiSha256: path.rootSpkiSha256,
    };
  };
}

/** Authenticate the supported direct KeyStore chain. Reject appended children
 * and ATTEST_KEY delegation instead of reading an attacker-added leaf extension.
 * Keystore's actual signing key must be the certificate bearing the first
 * attestation extension when traversing from the trusted root. */
export function verifyAndroidCertificatePath(
  presented: readonly Uint8Array[],
  trust: AndroidTrustSnapshot,
  now: Date,
  verifiedAtCreation: Date = now,
) {
  validateTrust(trust, now);
  if (
    !Number.isSafeInteger(verifiedAtCreation.getTime()) ||
    verifiedAtCreation.getTime() < 0 ||
    verifiedAtCreation > now
  )
    throw rejected("invalid_android_verification_time");
  if (
    presented.length < 4 ||
    presented.length > 5 ||
    presented.some((bytes) => !bytes.length || bytes.length > 16_384)
  )
    throw rejected("invalid_android_certificate_chain");
  try {
    const certificates = presented.map(
      (bytes) => new X509Certificate(Uint8Array.from(bytes).buffer),
    );
    const nodes = presented.map((bytes) => new NodeCertificate(bytes));
    if (
      nodes.some(
        (certificate, index) =>
          !certificate.raw.equals(Buffer.from(presented[index]!)),
      ) ||
      new Set(nodes.map((certificate) => certificate.fingerprint256)).size !==
        nodes.length
    )
      throw rejected("invalid_android_certificate_encoding");
    const root = nodes.at(-1)!;
    const rootSpkiSha256 = sha256(
      root.publicKey.export({ format: "der", type: "spki" }),
    ).toString("base64url");
    const anchor = trust.roots.find(
      (entry) => entry.spkiSha256 === rootSpkiSha256,
    );
    if (!anchor || root.subject !== root.issuer || !root.verify(root.publicKey))
      throw rejected("untrusted_android_certificate_root");
    const certificateSerials = nodes.map((certificate) =>
      normalizeSerial(certificate.serialNumber),
    );
    const denied = new Set(trust.revokedSerials);
    if (certificateSerials.some((serial) => denied.has(serial)))
      throw rejected("android_certificate_revoked");

    const intermediate = certificates.at(-2)!;
    const factory =
      anchor.allowFactoryExpiry &&
      certificates.length === 4 &&
      intermediate.subjectName.getField("2.5.4.5").length === 1;
    const rkp =
      certificates.length === 5 &&
      exactName(intermediate, "CN", "Droid CA2") &&
      exactName(intermediate, "O", "Google LLC");
    if (!factory && !rkp)
      throw rejected("unsupported_android_certificate_path");
    const provisioning = factory ? ("factory" as const) : ("rkp" as const);
    for (let index = 0; index < certificates.length; index++) {
      const certificate = certificates[index]!;
      const node = nodes[index]!;
      const extensions = certificate.extensions;
      if (
        new Set(extensions.map((entry) => entry.type)).size !==
          extensions.length ||
        extensions.some(
          (entry) => entry.critical && !knownCritical.has(entry.type),
        )
      )
        throw rejected("unsupported_android_certificate_extensions");
      const keyDescription = certificate.getExtension(KEY_DESCRIPTION);
      if ((index === 0 && !keyDescription) || (index !== 0 && keyDescription))
        throw rejected("android_attestation_extension_position");
      if (certificate.getExtension(PROVISIONING) && (index !== 1 || !rkp))
        throw rejected("android_provisioning_extension_position");
      if (index < certificates.length - 1) {
        const issuer = nodes[index + 1]!;
        const details = issuer.publicKey.asymmetricKeyDetails;
        if (
          (issuer.publicKey.asymmetricKeyType === "rsa" &&
            (details?.modulusLength ?? 0) < 2048) ||
          (issuer.publicKey.asymmetricKeyType === "ec" &&
            !["prime256v1", "secp384r1", "secp521r1"].includes(
              details?.namedCurve ?? "",
            )) ||
          !["rsa", "ec"].includes(issuer.publicKey.asymmetricKeyType ?? "")
        )
          throw rejected("weak_android_issuer_key");
        // Android factory paths do not universally obey generic PKIX CA
        // constraints. Authenticate exact name chaining and each signature as
        // the reference verifier does; RKP additionally enforces CA constraints.
        if (
          certificate.issuer !== certificates[index + 1]!.subject ||
          !node.verify(issuer.publicKey)
        )
          throw rejected("invalid_android_certificate_signature");
        const algorithm = certificate.signatureAlgorithm;
        if (
          !["ECDSA", "RSASSA-PKCS1-v1_5", "RSA-PSS"].includes(algorithm.name) ||
          !["SHA-256", "SHA-384", "SHA-512"].includes(algorithm.hash.name)
        )
          throw rejected("weak_android_certificate_signature");
      }
      // Android controls leaf validity. It is not a freshness assertion. RKP
      // intermediates expire normally; only reviewed factory paths allow expiry.
      if (
        index > 0 &&
        index < certificates.length - 1 &&
        (verifiedAtCreation < certificate.notBefore ||
          (!factory && verifiedAtCreation > certificate.notAfter))
      )
        throw rejected("android_certificate_outside_validity");
      if (rkp && index > 0) {
        const constraints = certificate.getExtension(BasicConstraintsExtension);
        const usage = certificate.getExtension(KeyUsagesExtension);
        if (
          !constraints?.ca ||
          !usage ||
          (usage.usages & KeyUsageFlags.keyCertSign) === 0 ||
          (constraints.pathLength !== undefined &&
            constraints.pathLength < index - 1)
        )
          throw rejected("invalid_android_ca_constraints");
      }
    }
    const leaf = certificates[0]!;
    const usage = leaf.getExtension(KeyUsagesExtension);
    if (
      leaf.getExtension(BasicConstraintsExtension)?.ca ||
      !usage ||
      (usage.usages & KeyUsageFlags.digitalSignature) === 0 ||
      (usage.usages & KeyUsageFlags.keyCertSign) !== 0
    )
      throw rejected("invalid_android_signing_key_usage");
    const key = nodes[0]!.publicKey;
    if (key.asymmetricKeyType !== "ec")
      throw rejected("invalid_android_signing_key");
    const jwk = key.export({ format: "jwk" });
    if (jwk.crv !== "P-256" || jwk.kty !== "EC" || !jwk.x || !jwk.y)
      throw rejected("invalid_android_signing_key");
    const dpopJkt = sha256(
      Buffer.from(
        JSON.stringify({ crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y }),
      ),
    ).toString("base64url");
    const attestationCertificate = certificates[1]!;
    let attestationSecurityLevel: "tee" | "strongbox" | undefined;
    if (rkp) {
      if (exactName(attestationCertificate, "O", "TEE"))
        attestationSecurityLevel = "tee";
      else if (exactName(attestationCertificate, "O", "StrongBox"))
        attestationSecurityLevel = "strongbox";
      else throw rejected("invalid_android_certificate_security_level");
    } else if (
      [attestationCertificate.subject, intermediate.subject].some((name) =>
        name.toLowerCase().includes("strongbox"),
      )
    ) {
      attestationSecurityLevel = "strongbox";
    }
    return {
      extension: new Uint8Array(leaf.getExtension(KEY_DESCRIPTION)!.value),
      publicKeySpki: key
        .export({ format: "der", type: "spki" })
        .toString("base64"),
      dpopJkt,
      provisioning,
      attestationSecurityLevel,
      certificateSerials,
      rootSpkiSha256,
    };
  } catch (error) {
    if (error instanceof DeviceAttestationError) throw error;
    throw rejected("invalid_android_certificate_chain");
  }
}
function validateTrust(trust: AndroidTrustSnapshot, now: Date) {
  if (
    !Number.isSafeInteger(now.getTime()) ||
    !Number.isSafeInteger(trust.fetchedAt.getTime()) ||
    !Number.isSafeInteger(trust.expiresAt.getTime()) ||
    trust.fetchedAt > now ||
    trust.expiresAt <= now ||
    trust.expiresAt.getTime() - trust.fetchedAt.getTime() > 86_400_000 ||
    !trust.version ||
    trust.version.length > 128 ||
    !trust.roots.length ||
    trust.roots.length > 16 ||
    trust.roots.some(
      (entry) =>
        !/^[A-Za-z0-9_-]{43}$/.test(entry.spkiSha256) ||
        typeof entry.allowFactoryExpiry !== "boolean",
    ) ||
    trust.revokedSerials.length > 100_000 ||
    trust.revokedSerials.some(
      (serial) => !/^(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(serial),
    )
  )
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_RETRY",
      stage: "certificate-chain",
      reason: "android_trust_unavailable",
      retryable: true,
    });
}
function normalizeSerial(value: string) {
  if (!/^[0-9a-f]{1,128}$/i.test(value))
    throw rejected("invalid_android_certificate_serial");
  return value.toLowerCase().replace(/^0+(?=.)/, "");
}
function exactName(
  certificate: X509Certificate,
  field: string,
  expected: string,
) {
  const values = certificate.subjectName.getField(field);
  return values.length === 1 && values[0] === expected;
}
function rejected(reason: string) {
  return rejection("certificate-chain", reason);
}
