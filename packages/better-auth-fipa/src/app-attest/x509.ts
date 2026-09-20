import "reflect-metadata";

import { X509Certificate as NodeX509Certificate } from "node:crypto";

import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
} from "@peculiar/x509";

import { rejection } from "../errors.js";
import { equalBytes } from "../protocol/crypto.js";
import {
  type AppAttestPlatform,
  verifyAppAttestPlatformPolicy,
} from "./platform-policy.js";
import { APPLE_APP_ATTESTATION_ROOT_CA_PEM } from "./root-certificate.js";

const APP_ATTEST_NONCE_OID = "1.2.840.113635.100.8.2";
const APP_ATTEST_ACL_BLOB_OID = "1.2.840.113635.100.8.6";
const APP_ATTEST_CREDENTIAL_EKU = "1.2.840.113635.100.4.24";
const ROOT_DER = decodePemCertificate(APPLE_APP_ATTESTATION_ROOT_CA_PEM);

export interface VerifiedCredentialCertificate {
  publicKeyRaw: Buffer;
  publicKeySpki: Buffer;
  nonce: Buffer;
}

export async function verifyAppAttestCertificateChain(
  presentedChain: Uint8Array[],
  platform: AppAttestPlatform,
  now = new Date(),
): Promise<VerifiedCredentialCertificate> {
  if (presentedChain.length < 2 || presentedChain.length > 4) {
    throw rejection("certificate-chain", "invalid_certificate_chain_length");
  }

  let certificates: X509Certificate[];
  let signatureCertificates: NodeX509Certificate[];
  try {
    certificates = presentedChain.map(
      (certificate) => new X509Certificate(toArrayBuffer(certificate)),
    );
    certificates.push(new X509Certificate(toArrayBuffer(ROOT_DER)));
    signatureCertificates = presentedChain.map(
      (certificate) => new NodeX509Certificate(Buffer.from(certificate)),
    );
    signatureCertificates.push(new NodeX509Certificate(ROOT_DER));
  } catch {
    throw rejection("certificate-chain", "invalid_certificate_encoding");
  }

  for (const certificate of certificates) {
    if (now < certificate.notBefore || now > certificate.notAfter) {
      throw rejection("certificate-chain", "certificate_outside_validity");
    }
  }

  for (let index = 0; index < certificates.length - 1; index += 1) {
    const certificate = certificates[index];
    const issuer = certificates[index + 1];
    const signatureCertificate = signatureCertificates[index];
    const signatureIssuer = signatureCertificates[index + 1];
    if (
      !certificate ||
      !issuer ||
      !signatureCertificate ||
      !signatureIssuer ||
      certificate.issuer !== issuer.subject ||
      !signatureCertificate.checkIssued(signatureIssuer)
    ) {
      throw rejection("certificate-chain", "certificate_issuer_mismatch");
    }
    if (!signatureCertificate.verify(signatureIssuer.publicKey)) {
      throw rejection("certificate-chain", "invalid_certificate_signature");
    }
  }

  const root = certificates.at(-1);
  if (!root || !equalBytes(ROOT_DER, certificateDer(root))) {
    throw rejection("certificate-chain", "untrusted_certificate_root");
  }

  const leaf = certificates[0];
  if (!leaf) {
    throw rejection("certificate-chain", "missing_credential_certificate");
  }
  verifyCertificateConstraints(leaf, certificates.slice(1));

  let publicKeyRaw: ArrayBuffer;
  let publicKeySpki: ArrayBuffer;
  try {
    const publicKey = await leaf.publicKey.export();
    if (
      publicKey.algorithm.name !== "ECDSA" ||
      !("namedCurve" in publicKey.algorithm) ||
      publicKey.algorithm.namedCurve !== "P-256"
    ) {
      throw new TypeError("Unexpected credential key algorithm");
    }
    publicKeyRaw = await globalThis.crypto.subtle.exportKey("raw", publicKey);
    publicKeySpki = await globalThis.crypto.subtle.exportKey("spki", publicKey);
  } catch {
    throw rejection("certificate-chain", "invalid_credential_public_key");
  }

  const nonceExtension = leaf.getExtension(APP_ATTEST_NONCE_OID);
  if (!nonceExtension) {
    throw rejection("nonce", "missing_attestation_nonce");
  }
  verifyAppAttestPlatformPolicy(
    platform,
    leaf.getExtension(APP_ATTEST_ACL_BLOB_OID)?.value,
  );

  return {
    publicKeyRaw: Buffer.from(publicKeyRaw),
    publicKeySpki: Buffer.from(publicKeySpki),
    nonce: decodeAppAttestNonce(nonceExtension.value),
  };
}

function verifyCertificateConstraints(
  leaf: X509Certificate,
  issuers: X509Certificate[],
): void {
  const leafConstraints = leaf.getExtension(BasicConstraintsExtension);
  if (leafConstraints?.ca) {
    throw rejection("certificate-chain", "credential_certificate_is_ca");
  }
  const leafUsage = leaf.getExtension(KeyUsagesExtension);
  const leafExtendedUsage = leaf.getExtension(ExtendedKeyUsageExtension);
  if (
    !leafUsage ||
    (leafUsage.usages & KeyUsageFlags.digitalSignature) === 0 ||
    (leafUsage.usages & KeyUsageFlags.keyCertSign) !== 0 ||
    !leafExtendedUsage ||
    leafExtendedUsage.usages.length !== 1 ||
    leafExtendedUsage.usages[0] !== APP_ATTEST_CREDENTIAL_EKU
  ) {
    throw rejection("certificate-chain", "invalid_credential_key_usage");
  }

  for (const issuer of issuers) {
    const constraints = issuer.getExtension(BasicConstraintsExtension);
    const usage = issuer.getExtension(KeyUsagesExtension);
    if (
      !constraints?.ca ||
      !usage ||
      (usage.usages & KeyUsageFlags.keyCertSign) === 0
    ) {
      throw rejection("certificate-chain", "invalid_ca_constraints");
    }
  }
}

function decodeAppAttestNonce(input: ArrayBuffer): Buffer {
  const bytes = Buffer.from(input);
  let offset = 0;
  const sequence = readDerElement(bytes, offset, 0x30);
  offset = sequence.contentStart;
  const context = readDerElement(bytes, offset, 0xa1);
  if (context.end !== sequence.end) {
    throw rejection("nonce", "invalid_attestation_nonce_extension");
  }
  const octets = readDerElement(bytes, context.contentStart, 0x04);
  if (octets.end !== context.end || octets.length !== 32) {
    throw rejection("nonce", "invalid_attestation_nonce_extension");
  }
  return Buffer.from(bytes.subarray(octets.contentStart, octets.end));
}

function readDerElement(
  bytes: Buffer,
  offset: number,
  expectedTag: number,
): { contentStart: number; end: number; length: number } {
  if (bytes[offset] !== expectedTag) {
    throw rejection("nonce", "invalid_attestation_nonce_extension");
  }
  const firstLength = bytes[offset + 1];
  if (firstLength === undefined) {
    throw rejection("nonce", "invalid_attestation_nonce_extension");
  }

  let length = 0;
  let contentStart = offset + 2;
  if (firstLength < 0x80) {
    length = firstLength;
  } else {
    const lengthBytes = firstLength & 0x7f;
    if (
      lengthBytes === 0 ||
      lengthBytes > 4 ||
      contentStart + lengthBytes > bytes.length
    ) {
      throw rejection("nonce", "invalid_attestation_nonce_extension");
    }
    if (bytes[contentStart] === 0) {
      throw rejection("nonce", "invalid_attestation_nonce_extension");
    }
    for (let index = 0; index < lengthBytes; index += 1) {
      length = length * 256 + (bytes[contentStart + index] ?? 0);
    }
    if (length < 0x80) {
      throw rejection("nonce", "invalid_attestation_nonce_extension");
    }
    contentStart += lengthBytes;
  }
  const end = contentStart + length;
  if (end > bytes.length) {
    throw rejection("nonce", "invalid_attestation_nonce_extension");
  }
  return { contentStart, end, length };
}

function decodePemCertificate(pem: string): Buffer {
  const body = pem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/gu, "");
  return Buffer.from(body, "base64");
}

function certificateDer(certificate: X509Certificate): Buffer {
  return Buffer.from(certificate.toString("base64"), "base64");
}

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  return Uint8Array.from(input).buffer;
}
