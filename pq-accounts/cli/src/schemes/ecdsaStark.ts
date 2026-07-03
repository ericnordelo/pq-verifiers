import { Signer, ec, num } from "starknet";
import type { PqSignatureScheme } from "./types.js";

function requirePrivateKey(input: { signer: { kind: string; privateKey?: string } }): string {
  if (input.signer.kind !== "private-key" || !input.signer.privateKey) {
    throw new Error("ecdsa-stark requires --private-key.");
  }
  return input.signer.privateKey;
}

function toFelt(value: bigint | string): string {
  return num.toHex(value);
}

export const ecdsaStarkScheme: PqSignatureScheme = {
  key: "ecdsa-stark",
  label: "ECDSA-STARK",
  accountContract: "EcdsaStarkAccount",
  signatureFelts: 2,
  publicKeyFelts: 1,
  description: "Signs transaction hashes with the STARK-curve ECDSA layout used by pqbench_ecdsa_stark: [r, s].",
  signerKinds: ["private-key"],
  async publicKey(input) {
    const privateKey = requirePrivateKey(input);
    return [toFelt(ec.starkCurve.getStarkKey(privateKey))];
  },
  constructorCalldata(publicKey) {
    if (publicKey.length !== 1) {
      throw new Error("ecdsa-stark constructor calldata requires exactly one public-key felt.");
    }
    return publicKey;
  },
  async signHash(input) {
    const privateKey = requirePrivateKey(input);
    const signature = ec.starkCurve.sign(input.hash, privateKey);
    return [toFelt(signature.r), toFelt(signature.s)];
  },
  async createStarknetSigner(input) {
    return new Signer(requirePrivateKey(input));
  }
};
