import "reflect-metadata";
import {
  X509CertificateGenerator,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  Extension,
} from "@peculiar/x509";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { model, encode } from "./key-description.fixture.js";

/** Cryptographic test authority, never a production Google trust anchor. */
export async function attestedKey(challenge: Buffer) {
  const keys = await Promise.all(
    Array.from({ length: 5 }, () =>
      crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ]),
    ),
  );
  const dates = {
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
  };
  const ca = () => [
    new BasicConstraintsExtension(true, undefined, true),
    new KeyUsagesExtension(KeyUsageFlags.keyCertSign, true),
  ];
  const root = await X509CertificateGenerator.createSelfSigned({
    name: "CN=Admission test root",
    keys: keys[0]!,
    ...dates,
    serialNumber: "100",
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: ca(),
  });
  const chain = [root];
  for (let index = 1; index < keys.length; index++) {
    const description = model();
    description.challenge = Buffer.from(challenge);
    const cert = await X509CertificateGenerator.create({
      subject: [
        "",
        "O=Google LLC, CN=Droid CA2",
        "O=Google LLC, CN=Droid CA3",
        "O=TEE, CN=Attestation",
        "CN=Android Keystore Key",
      ][index]!,
      issuer: chain.at(-1)!.subject,
      publicKey: keys[index]!.publicKey,
      signingKey: keys[index - 1]!.privateKey,
      ...dates,
      serialNumber: String(100 + index),
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions:
        index === 4
          ? [
              new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
              new Extension(
                "1.3.6.1.4.1.11129.2.1.17",
                false,
                Uint8Array.from(encode(description)).buffer,
              ),
            ]
          : ca(),
    });
    chain.push(cert);
  }
  const privateKey = createPrivateKey({
    key: Buffer.from(
      await crypto.subtle.exportKey("pkcs8", keys[4]!.privateKey),
    ),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" });
  const jkt = createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
    .digest("base64url");
  return {
    privateKey,
    publicKey,
    jwk,
    jkt,
    root: root.toString("pem"),
    chain: chain
      .reverse()
      .map((cert) => Buffer.from(cert.rawData).toString("base64")),
  };
}
