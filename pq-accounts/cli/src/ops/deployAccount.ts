import { hash } from "starknet";
import { createAccount } from "../starknet.js";
import type { Felt, PqSignatureScheme, SignerMaterial } from "../schemes/types.js";

export type DeployAccountResult = {
  address: Felt;
  transactionHash: Felt;
  constructorCalldata: Felt[];
};

/** Counterfactual address for an account class + constructor calldata + salt. */
export function computeAccountAddress(classHash: Felt, salt: Felt, constructorCalldata: Felt[]): Felt {
  return hash.calculateContractAddressFromHash(salt, classHash, constructorCalldata, 0);
}

/** Deploys an account with the scheme's signature adapter. The counterfactual address
 * must already hold fee funds. Constructor calldata defaults to the signer's public key
 * in the scheme's layout. */
export async function deployPqAccount(params: {
  rpcUrl: string;
  scheme: PqSignatureScheme;
  signerMaterial: SignerMaterial;
  classHash: Felt;
  salt: Felt;
  constructorCalldata?: Felt[];
}): Promise<DeployAccountResult> {
  const constructorCalldata =
    params.constructorCalldata ??
    params.scheme.constructorCalldata(await params.scheme.publicKey({ signer: params.signerMaterial }));
  const address = computeAccountAddress(params.classHash, params.salt, constructorCalldata);
  const account = await createAccount({
    rpcUrl: params.rpcUrl,
    accountAddress: address,
    scheme: params.scheme,
    signer: await params.scheme.createStarknetSigner({ signer: params.signerMaterial })
  });
  const response = await account.deployAccount(
    {
      classHash: params.classHash,
      addressSalt: params.salt,
      constructorCalldata,
      contractAddress: address
    },
    // Fee estimation must run the verifier: the default SKIP_VALIDATE estimate would
    // under-provision l2 gas for validation-heavy accounts.
    { skipValidate: false }
  );
  return { address, transactionHash: response.transaction_hash, constructorCalldata };
}
