import type { PqSignatureScheme } from "./types.js";
import { ExternalCommandStarknetSigner, runExternalSigner } from "./externalSigner.js";

export type ExternalSchemeOptions = {
  key: string;
  label?: string;
  accountContract?: string;
  signatureFelts?: number | "variable";
  publicKeyFelts?: number | "variable";
  description?: string;
  arrayPublicKey?: boolean;
};

export function createExternalScheme(options: ExternalSchemeOptions): PqSignatureScheme {
  const key = options.key;
  return {
    key,
    label: options.label ?? key,
    accountContract: options.accountContract ?? key,
    signatureFelts: options.signatureFelts ?? "variable",
    publicKeyFelts: options.publicKeyFelts ?? "variable",
    description: options.description ?? "Delegates signing to an external command that speaks the pq-verifiers signer JSON protocol.",
    signerKinds: ["external-command"],
    async publicKey(input) {
      const result = await runExternalSigner(input.signer, {
        scheme: key,
        action: "public-key",
        payload: {}
      });
      if (!result.publicKey) {
        throw new Error("external signer response must include a publicKey array.");
      }
      return result.publicKey;
    },
    constructorCalldata(publicKey) {
      return options.arrayPublicKey ? [`0x${publicKey.length.toString(16)}`, ...publicKey] : publicKey;
    },
    async signHash(input) {
      const result = await runExternalSigner(input.signer, {
        scheme: key,
        action: "sign-hash",
        payload: { hash: input.hash }
      });
      if (!result.signature) {
        throw new Error("external signer response must include a signature array.");
      }
      return result.signature;
    },
    async createStarknetSigner(input) {
      return new ExternalCommandStarknetSigner(key, input);
    }
  };
}
