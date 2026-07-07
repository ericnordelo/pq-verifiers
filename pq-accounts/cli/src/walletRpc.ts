import { typedData as typedDataUtil, type Call } from "starknet";
import { createProvider } from "./starknet.js";
import { executeCalls } from "./ops/execute.js";
import { resolveScheme } from "./schemes/registry.js";
import type { Felt, PqSignatureScheme, SignerMaterial } from "./schemes/types.js";

/** Configuration the daemon resolves once at startup. */
export type WalletContext = {
  rpcUrl: string;
  accountAddress: Felt;
  scheme: PqSignatureScheme;
  signerMaterial: SignerMaterial;
  /** Optional sink for advisory notices (e.g. an ignored chain switch). */
  warn?: (message: string) => void;
};

/** One wallet-API request message, as sent by get-starknet / starknet.js dapps. */
export type WalletRequest = {
  type: string;
  params?: unknown;
};

function asCall(value: Record<string, unknown>): Call {
  const contractAddress = (value.contract_address ?? value.contractAddress) as string;
  const entrypoint = (value.entry_point ?? value.entrypoint) as string;
  const calldata = (value.calldata ?? []) as string[];
  if (!contractAddress || !entrypoint) {
    throw new Error("invoke call needs contract_address and entry_point");
  }
  return { contractAddress, entrypoint, calldata };
}

/** Handles one wallet JSON-RPC message against the configured account. Covers the
 * message types dapp connect flows and contract writes use; unknown types return an
 * error the caller reports back to the page. */
export async function handleWalletRequest(
  ctx: WalletContext,
  request: WalletRequest
): Promise<unknown> {
  const params = (request.params ?? {}) as Record<string, unknown>;
  switch (request.type) {
    case "wallet_supportedSpecs":
      return ["0.7.1", "0.8.1"];

    case "wallet_supportedWalletApi":
      return ["0.7.2"];

    case "wallet_getPermissions":
      return ["accounts"];

    case "wallet_requestAccounts":
      return [ctx.accountAddress];

    case "wallet_requestChainId":
      return await createProvider(ctx.rpcUrl).getChainId();

    case "wallet_switchStarknetChain": {
      // The dapp asks the wallet to move to its network. This wallet operates on exactly
      // one network (whatever PQ_RPC points at) and always submits there, so the request
      // is advisory: accept it to let the connect handshake complete, but warn loudly on
      // a mismatch — the dapp may then build or display for the wrong network even though
      // transactions still go to PQ_RPC's chain.
      const requested = params.chainId as string | undefined;
      const current = await createProvider(ctx.rpcUrl).getChainId();
      if (requested && requested !== current) {
        ctx.warn?.(
          `dapp asked to switch to chain ${requested}, but this wallet is on ${current} ` +
            "(PQ_RPC). Accepting; transactions still go to PQ_RPC's network. Match the " +
            "dapp's network selector to PQ_RPC to avoid confusion."
        );
      }
      return true;
    }

    case "wallet_addStarknetChain":
    case "wallet_watchAsset":
      // No custom chains or asset tracking to persist; report success so connect flows
      // that probe these do not stall.
      return true;

    case "wallet_deploymentData":
      throw new Error("account is already deployed; deployment data is not exposed");

    case "wallet_addInvokeTransaction": {
      const rawCalls = (params.calls ?? []) as Record<string, unknown>[];
      if (!Array.isArray(rawCalls) || rawCalls.length === 0) {
        throw new Error("wallet_addInvokeTransaction needs a non-empty calls array");
      }
      const result = await executeCalls({
        rpcUrl: ctx.rpcUrl,
        scheme: ctx.scheme,
        signerMaterial: ctx.signerMaterial,
        accountAddress: ctx.accountAddress,
        calls: rawCalls.map(asCall)
      });
      return { transaction_hash: result.transactionHash };
    }

    case "wallet_signTypedData": {
      // Params are the SNIP-12 typed data (some dapps wrap it in { typedData }).
      const data = (params.typedData ?? params) as Parameters<
        typeof typedDataUtil.getMessageHash
      >[0];
      const hash = typedDataUtil.getMessageHash(data, ctx.accountAddress);
      return await ctx.scheme.signHash({ hash, signer: ctx.signerMaterial });
    }

    default:
      throw new Error(`unsupported wallet request type: ${request.type}`);
  }
}

/** Resolves the daemon's wallet context from PQ_* environment values. */
export function walletContextFromEnv(params: {
  rpcUrl: string;
  accountAddress: Felt;
  schemeKey: string;
  signerMaterial: SignerMaterial;
  warn?: (message: string) => void;
}): WalletContext {
  return {
    rpcUrl: params.rpcUrl,
    accountAddress: params.accountAddress,
    scheme: resolveScheme(params.schemeKey, true),
    signerMaterial: params.signerMaterial,
    warn: params.warn
  };
}
