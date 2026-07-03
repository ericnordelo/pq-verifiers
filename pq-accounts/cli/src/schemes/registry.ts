import type { PqSignatureScheme } from "./types.js";
import { ecdsaStarkScheme } from "./ecdsaStark.js";
import { createExternalScheme } from "./externalScheme.js";

const falcon512Scheme = createExternalScheme({
  key: "falcon-512",
  label: "Falcon-512",
  accountContract: "Falcon512Account",
  signatureFelts: 60,
  publicKeyFelts: 29,
  arrayPublicKey: true,
  description: "Uses the Falcon-512 hint account. Signing is delegated to an external signer that returns the 60-felt hint signature layout."
});

const falcon512DirectScheme = createExternalScheme({
  key: "falcon-512-direct",
  label: "Falcon-512 direct",
  accountContract: "Falcon512DirectAccount",
  signatureFelts: 31,
  publicKeyFelts: 29,
  arrayPublicKey: true,
  description: "Uses the Falcon-512 direct account. Signing is delegated to an external signer that returns the 31-felt direct signature layout."
});

const builtInSchemes = new Map<string, PqSignatureScheme>([
  [ecdsaStarkScheme.key, ecdsaStarkScheme],
  ["ecdsa_stark", ecdsaStarkScheme],
  [falcon512Scheme.key, falcon512Scheme],
  ["falcon_512", falcon512Scheme],
  [falcon512DirectScheme.key, falcon512DirectScheme],
  ["falcon_512_direct", falcon512DirectScheme]
]);

export function listSchemes(): PqSignatureScheme[] {
  return [ecdsaStarkScheme, falcon512Scheme, falcon512DirectScheme];
}

export function resolveScheme(key: string, allowExternal: boolean): PqSignatureScheme {
  const normalized = key.trim();
  const builtIn = builtInSchemes.get(normalized);
  if (builtIn) {
    return builtIn;
  }
  if (allowExternal) {
    return createExternalScheme({ key: normalized });
  }
  throw new Error(`unknown scheme "${key}". Run "pq-accounts accounts" to list supported accounts.`);
}
