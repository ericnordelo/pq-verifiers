import type { RpcProvider } from "starknet";
import type { Felt } from "../schemes/types.js";

/** STRK (fee token for v3 transactions); the same address on mainnet, Sepolia, and devnet. */
export const STRK_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

export type AccountStatus = {
  address: Felt;
  deployed: boolean;
  classHash?: string;
  nonce?: Felt;
  strkBalance?: string;
};

/** Reads deployment state, nonce, and STRK balance for an account address. */
export async function accountStatus(provider: RpcProvider, address: Felt): Promise<AccountStatus> {
  let classHash: string | undefined;
  try {
    classHash = await provider.getClassHashAt(address);
  } catch {
    classHash = undefined;
  }
  let strkBalance: string | undefined;
  try {
    const balance = await provider.callContract({
      contractAddress: STRK_ADDRESS,
      entrypoint: "balance_of",
      calldata: [address]
    });
    strkBalance = (BigInt(balance[0]) + (BigInt(balance[1]) << 128n)).toString();
  } catch {
    strkBalance = undefined;
  }
  if (!classHash) {
    return { address, deployed: false, strkBalance };
  }
  const nonce = await provider.getNonceForAddress(address);
  return { address, deployed: true, classHash, nonce, strkBalance };
}
