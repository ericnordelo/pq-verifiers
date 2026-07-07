import path from "node:path";
import { stark } from "starknet";
import { createProvider } from "../starknet.js";
import { mint, predeployedAccounts } from "../devnet.js";
import { demoKeyPath, falconSignerMaterial } from "../options.js";
import { resolveScheme } from "../schemes/registry.js";
import type { Felt, SignerMaterial } from "../schemes/types.js";
import { ensureDeclared } from "./declare.js";
import { computeAccountAddress, deployPqAccount } from "./deployAccount.js";
import { executeCalls } from "./execute.js";
import { STRK_ADDRESS } from "./status.js";

/** 1000 STRK, minted to the counterfactual address before deployment. */
const PREFUND_FRI = 1000n * 10n ** 18n;
/** 1 STRK, transferred back to the funder as the demo invoke. */
const DEMO_TRANSFER_FRI = 10n ** 18n;

export type QuickstartParams = {
  rpcUrl: string;
  schemeKey: string;
  /** Overrides the default signer (demo Falcon key / random ECDSA key). */
  signerMaterial?: SignerMaterial;
  salt?: Felt;
  /** Progress sink; each line describes one completed step. */
  log?: (line: string) => void;
};

export type QuickstartResult = {
  scheme: string;
  contract: string;
  classHash: string;
  address: Felt;
  usedDemoKey: boolean;
  declare: { transactionHash?: Felt; alreadyDeclared: boolean };
  deploy: { transactionHash: Felt; l2Gas?: string; feeFri?: string };
  transfer: { transactionHash: Felt; l2Gas?: string; feeFri?: string };
};

function gasAndFee(receipt: unknown): { l2Gas?: string; feeFri?: string } {
  const r = receipt as {
    actual_fee?: { amount?: string };
    execution_resources?: { l2_gas?: number | string };
  };
  const l2Gas = r.execution_resources?.l2_gas;
  const fee = r.actual_fee?.amount;
  return {
    l2Gas: l2Gas === undefined ? undefined : BigInt(l2Gas).toString(),
    feeFri: fee === undefined ? undefined : BigInt(fee).toString()
  };
}

/** Default signing material per scheme family: a fresh random key for ecdsa-stark, the
 * committed INSECURE demo key for the Falcon schemes (requires a falcon.py checkout via
 * PQ_FALCON_PY). */
function defaultSigner(schemeKey: string): { material: SignerMaterial; usedDemoKey: boolean } {
  if (schemeKey === "ecdsa-stark" || schemeKey === "ecdsa_stark") {
    return { material: { kind: "private-key", privateKey: stark.randomAddress() }, usedDemoKey: false };
  }
  const falconPy = process.env.PQ_FALCON_PY;
  if (!falconPy) {
    throw new Error(
      "Falcon quickstart needs a falcon.py checkout: " +
        "git clone https://github.com/tprest/falcon.py, then set PQ_FALCON_PY to its path."
    );
  }
  const keyFile = process.env.PQ_FALCON_KEY ?? demoKeyPath();
  return {
    material: falconSignerMaterial(falconPy, keyFile),
    usedDemoKey: path.resolve(keyFile) === demoKeyPath()
  };
}

/** The devnet golden path: declare the scheme's account class, derive the account
 * address from the signer's public key, prefund it, deploy, and send one transfer —
 * reporting the transaction hashes, gas, and fees of each on-chain step. */
export async function quickstart(params: QuickstartParams): Promise<QuickstartResult> {
  const log = params.log ?? (() => {});
  const scheme = resolveScheme(params.schemeKey, true);
  const provider = createProvider(params.rpcUrl);

  const funders = await predeployedAccounts(params.rpcUrl);
  if (!funders || funders.length === 0) {
    throw new Error(
      `no devnet at ${params.rpcUrl}. Start one with "starknet-devnet --seed 0" ` +
        "(quickstart is devnet-only; see USAGE.md for public networks)."
    );
  }
  const funder = funders[0]!;
  log(`devnet at ${params.rpcUrl}, funder ${funder.address}`);

  const { material, usedDemoKey } = params.signerMaterial
    ? { material: params.signerMaterial, usedDemoKey: false }
    : defaultSigner(scheme.key);
  if (usedDemoKey) {
    log("signer: committed demo key (INSECURE, devnet only)");
  }

  const declared = await ensureDeclared({
    provider,
    funderAddress: funder.address,
    funderPrivateKey: funder.privateKey,
    contractName: scheme.accountContract
  });
  log(
    declared.alreadyDeclared
      ? `class ${declared.classHash} already declared`
      : `declared ${scheme.accountContract}: ${declared.classHash}`
  );

  const publicKey = await scheme.publicKey({ signer: material });
  const constructorCalldata = scheme.constructorCalldata(publicKey);
  const salt = params.salt ?? stark.randomAddress();
  const address = computeAccountAddress(declared.classHash, salt, constructorCalldata);
  await mint(params.rpcUrl, address, PREFUND_FRI);
  log(`prefunded ${address} with 1000 STRK`);

  const deployed = await deployPqAccount({
    rpcUrl: params.rpcUrl,
    scheme,
    signerMaterial: material,
    classHash: declared.classHash,
    salt,
    constructorCalldata
  });
  const deployReceipt = await provider.waitForTransaction(deployed.transactionHash);
  const deployStats = gasAndFee(deployReceipt);
  log(`deployed account (${scheme.key} validated the deployment signature on-chain)`);

  const transfer = await executeCalls({
    rpcUrl: params.rpcUrl,
    scheme,
    signerMaterial: material,
    accountAddress: address,
    calls: [
      {
        contractAddress: STRK_ADDRESS,
        entrypoint: "transfer",
        calldata: [funder.address, DEMO_TRANSFER_FRI.toString(), "0"]
      }
    ]
  });
  const transferReceipt = await provider.waitForTransaction(transfer.transactionHash);
  const transferStats = gasAndFee(transferReceipt);
  log(`transferred 1 STRK back to the funder (${scheme.key} validated the invoke on-chain)`);

  return {
    scheme: scheme.key,
    contract: scheme.accountContract,
    classHash: declared.classHash,
    address,
    usedDemoKey,
    declare: { transactionHash: declared.transactionHash, alreadyDeclared: declared.alreadyDeclared },
    deploy: { transactionHash: deployed.transactionHash, ...deployStats },
    transfer: { transactionHash: transfer.transactionHash, ...transferStats }
  };
}
