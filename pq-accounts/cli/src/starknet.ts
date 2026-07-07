import { Account, RpcProvider, logger, type Call } from "starknet";
import type { Felt, PqSignatureScheme } from "./schemes/types.js";

// Starknet.js logs fee-estimation heuristics at WARN; keep command output clean.
logger.setLogLevel("ERROR");

type SupportedAccountVersion = "0x3";

function asSupportedAccountVersion(version: Felt | undefined): SupportedAccountVersion | undefined {
  if (!version) {
    return undefined;
  }
  if (version === "0x3") {
    return version;
  }
  throw new Error("--version must be 0x3 for Starknet.js v10 account transactions.");
}

export function createProvider(rpcUrl: string): RpcProvider {
  return new RpcProvider({ nodeUrl: rpcUrl });
}

export async function createAccount(params: {
  rpcUrl: string;
  accountAddress: Felt;
  scheme: PqSignatureScheme;
  signer: unknown;
  cairoVersion?: "0" | "1";
  transactionVersion?: Felt;
}): Promise<Account> {
  const provider = createProvider(params.rpcUrl);
  return new Account({
    provider,
    address: params.accountAddress,
    signer: params.signer as never,
    cairoVersion: params.cairoVersion,
    transactionVersion: asSupportedAccountVersion(params.transactionVersion)
  });
}

export function buildCall(contractAddress: Felt, entrypoint: string, calldata: Felt[]): Call {
  return {
    contractAddress,
    entrypoint,
    calldata
  };
}
