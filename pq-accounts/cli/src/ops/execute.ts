import type { Call } from "starknet";
import { createAccount } from "../starknet.js";
import type { Felt, PqSignatureScheme, SignerMaterial } from "../schemes/types.js";

export type ExecuteResult = {
  transactionHash: Felt;
};

/** Sends an invoke transaction from a deployed account through the scheme's
 * signature adapter. */
export async function executeCalls(params: {
  rpcUrl: string;
  scheme: PqSignatureScheme;
  signerMaterial: SignerMaterial;
  accountAddress: Felt;
  calls: Call[];
  nonce?: Felt;
}): Promise<ExecuteResult> {
  const account = await createAccount({
    rpcUrl: params.rpcUrl,
    accountAddress: params.accountAddress,
    scheme: params.scheme,
    signer: await params.scheme.createStarknetSigner({ signer: params.signerMaterial })
  });
  const response = await account.execute(params.calls, {
    nonce: params.nonce,
    // Fee estimation must run the verifier: the default SKIP_VALIDATE estimate would
    // under-provision l2 gas for validation-heavy accounts.
    skipValidate: false
  });
  return { transactionHash: response.transaction_hash };
}
