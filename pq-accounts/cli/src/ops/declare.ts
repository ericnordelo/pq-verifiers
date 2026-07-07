import { Account, RpcProvider } from "starknet";
import { loadContractArtifacts } from "../artifacts.js";
import type { Felt } from "../schemes/types.js";

export type DeclareResult = {
  contractName: string;
  classHash: string;
  transactionHash?: Felt;
  alreadyDeclared: boolean;
};

/** Declares an account class with a funded ECDSA account, skipping the transaction
 * when the class hash is already known to the network. */
export async function ensureDeclared(params: {
  provider: RpcProvider;
  funderAddress: Felt;
  funderPrivateKey: Felt;
  contractName: string;
}): Promise<DeclareResult> {
  const artifacts = loadContractArtifacts(params.contractName);
  try {
    await params.provider.getClassByHash(artifacts.classHash);
    return { contractName: params.contractName, classHash: artifacts.classHash, alreadyDeclared: true };
  } catch {
    // Not declared yet.
  }
  const funder = new Account({
    provider: params.provider,
    address: params.funderAddress,
    signer: params.funderPrivateKey
  });
  const response = await funder.declare({ contract: artifacts.sierra, casm: artifacts.casm });
  await params.provider.waitForTransaction(response.transaction_hash);
  return {
    contractName: params.contractName,
    classHash: artifacts.classHash,
    transactionHash: response.transaction_hash,
    alreadyDeclared: false
  };
}
