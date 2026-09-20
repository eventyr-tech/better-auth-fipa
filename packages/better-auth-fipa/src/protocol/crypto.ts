import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export function sha256(input: Uint8Array): Buffer {
  return createHash("sha256").update(input).digest();
}

export function credentialLookupKey(input: {
  provider: string;
  applicationId: string;
  keyId: Uint8Array;
}): string {
  const hash = createHash("sha256");
  for (const value of [
    Buffer.from(input.provider, "utf8"),
    Buffer.from(input.applicationId, "utf8"),
    Buffer.from(input.keyId),
  ]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.length);
    hash.update(length);
    hash.update(value);
  }
  return hash.digest("hex");
}

export function hmacSha256(secret: string, input: string): string {
  return createHmac("sha256", secret).update(input, "utf8").digest("hex");
}

export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    timingSafeEqual(Buffer.from(left), Buffer.from(right))
  );
}
