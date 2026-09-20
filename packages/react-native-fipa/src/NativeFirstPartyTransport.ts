import type { TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

export interface Spec extends TurboModule {
  randomToken(): Promise<string>;
  transaction(): Promise<{ id: string; verifier: string; challenge: string }>;
  prepareDpop(alias: string): Promise<string>;
  inspectDpop(alias: string): Promise<string>;
  removeDpop(alias: string, expectedThumbprint: string): Promise<void>;
  signDpop(
    alias: string,
    expectedThumbprint: string,
    url: string,
    method: string,
    accessToken: string | null,
    nonce: string | null,
  ): Promise<string>;
  send(
    requestId: string,
    url: string,
    method: string,
    headersJSON: string,
    body: string | null,
    maximumResponseBytes: number,
    timeoutMilliseconds: number,
    allowInsecureLoopback: boolean,
  ): Promise<{
    url: string;
    status: number;
    headersJSON: string;
    body: string;
  }>;
  cancel(requestId: string): Promise<void>;
  openBrowser(
    requestId: string,
    url: string,
    redirectUri: string,
    timeoutMilliseconds: number,
    allowInsecureLoopback: boolean,
  ): Promise<string>;
  cancelBrowser(requestId: string): Promise<void>;
}
export default TurboModuleRegistry.get<Spec>(
  "DeviceAttestationFirstPartyTransport",
);
