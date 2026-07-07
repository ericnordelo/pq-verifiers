import type { Felt } from "./schemes/types.js";

/** A funded account predeployed by starknet-devnet. */
export type PredeployedAccount = {
  address: Felt;
  privateKey: Felt;
};

async function devnetRpc<T>(rpcUrl: string, method: string, paramsJson: string): Promise<T> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: `{"jsonrpc":"2.0","id":1,"method":"${method}","params":${paramsJson}}`
  });
  if (!response.ok) {
    throw new Error(`${method} failed with HTTP ${response.status}`);
  }
  const body = (await response.json()) as { result?: T; error?: { message: string } };
  if (body.error) {
    throw new Error(`${method} failed: ${body.error.message}`);
  }
  return body.result as T;
}

/** Returns the devnet predeployed accounts, or null when the RPC is not a devnet. */
export async function predeployedAccounts(rpcUrl: string): Promise<PredeployedAccount[] | null> {
  try {
    const result = await devnetRpc<{ address: string; private_key: string }[]>(
      rpcUrl,
      "devnet_getPredeployedAccounts",
      "{}"
    );
    return result.map((account) => ({ address: account.address, privateKey: account.private_key }));
  } catch {
    return null;
  }
}

/** Mints `amount` FRI (STRK) to `address` on a devnet. The amount is serialized
 * manually: minting amounts exceed Number.MAX_SAFE_INTEGER. */
export async function mint(rpcUrl: string, address: Felt, amount: bigint): Promise<void> {
  await devnetRpc(
    rpcUrl,
    "devnet_mint",
    `{"address":"${address}","amount":${amount.toString()},"unit":"FRI"}`
  );
}

/** Resolves the funded ECDSA account used to declare classes: explicit values first,
 * then PQ_FUNDER_ADDRESS / PQ_FUNDER_PRIVATE_KEY, then the first devnet predeployed
 * account. */
export async function resolveFunder(
  rpcUrl: string,
  explicit?: { address?: Felt; privateKey?: Felt }
): Promise<PredeployedAccount> {
  const address = explicit?.address ?? process.env.PQ_FUNDER_ADDRESS;
  const privateKey = explicit?.privateKey ?? process.env.PQ_FUNDER_PRIVATE_KEY;
  if (address && privateKey) {
    return { address, privateKey };
  }
  if (address || privateKey) {
    throw new Error("a funder needs both an address and a private key.");
  }
  const accounts = await predeployedAccounts(rpcUrl);
  if (accounts && accounts.length > 0) {
    return accounts[0]!;
  }
  throw new Error(
    "no funder available: pass --funder-address/--funder-private-key (or set " +
      "PQ_FUNDER_ADDRESS/PQ_FUNDER_PRIVATE_KEY), or point --rpc at a devnet."
  );
}
