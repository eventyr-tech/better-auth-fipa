import { expect, it } from "vitest";
import {
  createAdmissionTransport,
  nativeOperation,
} from "./adapter-operations.ts";
import { FirstPartyClientError } from "./errors.ts";

it("preserves missing-key recovery and suppresses native exception details", async () => {
  await expect(
    nativeOperation(() =>
      Promise.reject(
        Object.assign(new Error("private"), { code: "key_missing" }),
      ),
    ),
  ).rejects.toMatchObject({ code: "registration_recovery_required" });
  const error = await nativeOperation(() =>
    Promise.reject(new Error("private")),
  ).catch((e: unknown) => e);
  expect(error).toEqual(new FirstPartyClientError("operation_failed"));
  expect(String(error)).not.toContain("private");
});
it("cancellation wins when a native operation or transport fails after abort", async () => {
  for (const transport of [false, true]) {
    const controller = new AbortController();
    const fail = () => {
      controller.abort();
      return Promise.reject(new Error("private"));
    };
    const result = transport
      ? createAdmissionTransport("https://auth.example", fail)(
          "/challenge",
          {},
          controller.signal,
        )
      : nativeOperation(fail, controller.signal);
    await expect(result).rejects.toMatchObject({ code: "cancelled" });
  }
});
it("normalizes transport failures while retaining invalid-response errors", async () => {
  for (const [failure, expected] of [
    [new Error("private"), "request_failed"],
    [new FirstPartyClientError("invalid_response"), "invalid_response"],
    [
      Object.assign(new Error("private"), { code: "http_response_too_large" }),
      "invalid_response",
    ],
  ] as const) {
    const post = createAdmissionTransport("https://auth.example", () =>
      Promise.reject(failure),
    );
    await expect(
      post("/challenge", {}, new AbortController().signal),
    ).rejects.toMatchObject({ code: expected });
  }
});

it.each([
  "app_attest_unavailable",
  "simulator_unavailable",
  "key_unavailable",
  "key_locked",
  "key_invalid_input",
] as const)(
  "preserves actionable %s without secret native details",
  async (code) => {
    const error = await nativeOperation(() =>
      Promise.reject(
        Object.assign(new Error("password otp token proof"), { code }),
      ),
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(FirstPartyClientError);
    expect(error).toMatchObject({ code });
    expect(JSON.stringify(error)).not.toContain("password otp token proof");
  },
);
