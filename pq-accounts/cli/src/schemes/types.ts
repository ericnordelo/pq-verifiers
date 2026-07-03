import type { Call } from "starknet";

export type Felt = string;

export type SignerMaterial =
  | {
      kind: "private-key";
      privateKey: Felt;
    }
  | {
      kind: "external-command";
      command: string;
      args: string[];
    };

export type SignHashInput = {
  hash: Felt;
  signer: SignerMaterial;
};

export type CreateStarknetSignerInput = {
  signer: SignerMaterial;
};

export type ExternalSignerRequest = {
  scheme: string;
  action: "public-key" | "sign-hash" | "sign-transaction" | "sign-deploy-account";
  payload: unknown;
};

/** Signature adapter for one verifier layout consumed by a pq-verifiers account. */
export type PqSignatureScheme = {
  key: string;
  label: string;
  accountContract: string;
  signatureFelts: number | "variable";
  publicKeyFelts: number | "variable";
  description: string;
  signerKinds: SignerMaterial["kind"][];
  publicKey: (input: CreateStarknetSignerInput) => Promise<Felt[]>;
  constructorCalldata: (publicKey: Felt[]) => Felt[];
  /** Signs a known Starknet transaction hash and returns verifier-ordered signature felts. */
  signHash: (input: SignHashInput) => Promise<Felt[]>;
  /** Returns the signer object consumed by Starknet.js Account transaction helpers. */
  createStarknetSigner: (input: CreateStarknetSignerInput) => Promise<unknown>;
};

export type ExecuteInput = {
  accountAddress: Felt;
  calls: Call[];
  nonce?: Felt;
  version?: Felt;
  maxFee?: Felt;
};
