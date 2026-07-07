#!/usr/bin/env node
// Local MCP server exposing the pq-accounts operations to LLM clients over stdio.
//
// Configuration is environment-only (set it in the MCP client's server config):
//   PQ_RPC                 JSON-RPC endpoint (default http://127.0.0.1:5050/rpc)
//   PQ_SCHEME              default scheme key (default falcon-512-shake)
//   PQ_FALCON_PY           falcon.py checkout, required for Falcon schemes
//   PQ_FALCON_KEY          Falcon key file (defaults to the committed INSECURE demo key)
//   PQ_PRIVATE_KEY         private key for ecdsa-stark
//   PQ_FUNDER_ADDRESS/_PRIVATE_KEY  funded account for declarations off-devnet
//   PQ_PYTHON              python executable for the bundled signer (default python3)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createProvider } from "./starknet.js";
import { demoKeyPath, falconSignerMaterial, parseSignerOptions } from "./options.js";
import { listSchemes, resolveScheme } from "./schemes/registry.js";
import type { SignerMaterial } from "./schemes/types.js";
import { mint, predeployedAccounts, resolveFunder } from "./devnet.js";
import { ensureDeclared } from "./ops/declare.js";
import { computeAccountAddress, deployPqAccount } from "./ops/deployAccount.js";
import { executeCalls } from "./ops/execute.js";
import { accountStatus } from "./ops/status.js";
import { quickstart } from "./ops/quickstart.js";

const DEFAULT_RPC = process.env.PQ_RPC ?? "http://127.0.0.1:5050/rpc";
const DEFAULT_SCHEME = process.env.PQ_SCHEME ?? "falcon-512-shake";

/** Signing material from the PQ_* environment, per scheme family. */
function envSigner(schemeKey: string): SignerMaterial {
  if (schemeKey.startsWith("falcon") && process.env.PQ_FALCON_PY) {
    return falconSignerMaterial(process.env.PQ_FALCON_PY, process.env.PQ_FALCON_KEY ?? demoKeyPath());
  }
  return parseSignerOptions({});
}

function ok(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function fail(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text" as const, text: message }], isError: true };
}

const rpcArg = z.string().url().optional().describe(`JSON-RPC endpoint (default ${DEFAULT_RPC})`);
const schemeArg = z.string().optional().describe(`scheme key (default ${DEFAULT_SCHEME})`);

const server = new McpServer({ name: "pq-accounts", version: "0.1.0" });

server.registerTool(
  "list_schemes",
  {
    description:
      "List the post-quantum account schemes: keys, account contracts, and signature/public-key felt layouts."
  },
  async () => ok(listSchemes().map(({ key, label, accountContract, signatureFelts, publicKeyFelts }) => ({
    key,
    label,
    accountContract,
    signatureFelts,
    publicKeyFelts
  })))
);

server.registerTool(
  "account_status",
  {
    description: "Report deployment state, class hash, nonce, and STRK balance of an account address.",
    inputSchema: { address: z.string().describe("account address"), rpc: rpcArg }
  },
  async ({ address, rpc }) => {
    try {
      return ok(await accountStatus(createProvider(rpc ?? DEFAULT_RPC), address));
    } catch (error) {
      return fail(error);
    }
  }
);

server.registerTool(
  "declare",
  {
    description:
      "Declare a scheme's account class with a funded account (devnet predeployed funder by default). Idempotent.",
    inputSchema: { scheme: schemeArg, rpc: rpcArg }
  },
  async ({ scheme, rpc }) => {
    try {
      const rpcUrl = rpc ?? DEFAULT_RPC;
      const resolved = resolveScheme(scheme ?? DEFAULT_SCHEME, true);
      const funder = await resolveFunder(rpcUrl);
      return ok(
        await ensureDeclared({
          provider: createProvider(rpcUrl),
          funderAddress: funder.address,
          funderPrivateKey: funder.privateKey,
          contractName: resolved.accountContract
        })
      );
    } catch (error) {
      return fail(error);
    }
  }
);

server.registerTool(
  "deploy_account",
  {
    description:
      "Deploy a post-quantum account: derives the address from the configured signer's public key, " +
      "declares the class and prefunds via devnet mint when needed, then sends the deploy-account " +
      "transaction (validated on-chain by the scheme's verifier).",
    inputSchema: {
      scheme: schemeArg,
      salt: z.string().optional().describe("deployment salt (default: random)"),
      rpc: rpcArg
    }
  },
  async ({ scheme, salt, rpc }) => {
    try {
      const rpcUrl = rpc ?? DEFAULT_RPC;
      const resolved = resolveScheme(scheme ?? DEFAULT_SCHEME, true);
      const material = envSigner(resolved.key);
      const provider = createProvider(rpcUrl);
      const funder = await resolveFunder(rpcUrl);
      const declared = await ensureDeclared({
        provider,
        funderAddress: funder.address,
        funderPrivateKey: funder.privateKey,
        contractName: resolved.accountContract
      });
      const constructorCalldata = resolved.constructorCalldata(
        await resolved.publicKey({ signer: material })
      );
      const useSalt = salt ?? `0x${Date.now().toString(16)}${Math.floor(Math.random() * 0xffff).toString(16)}`;
      const address = computeAccountAddress(declared.classHash, useSalt, constructorCalldata);
      if (await predeployedAccounts(rpcUrl)) {
        await mint(rpcUrl, address, 1000n * 10n ** 18n);
      }
      const deployed = await deployPqAccount({
        rpcUrl,
        scheme: resolved,
        signerMaterial: material,
        classHash: declared.classHash,
        salt: useSalt,
        constructorCalldata
      });
      const receipt = await provider.waitForTransaction(deployed.transactionHash);
      return ok({ scheme: resolved.key, classHash: declared.classHash, ...deployed, receipt });
    } catch (error) {
      return fail(error);
    }
  }
);

server.registerTool(
  "execute",
  {
    description:
      "Send an invoke transaction from a deployed post-quantum account. The transaction hash is " +
      "signed by the configured signer and validated on-chain by the scheme's verifier.",
    inputSchema: {
      account: z.string().describe("deployed account address"),
      to: z.string().describe("target contract address"),
      entrypoint: z.string().describe("target entrypoint name, e.g. transfer"),
      calldata: z.array(z.string()).default([]).describe("call calldata felts"),
      scheme: schemeArg,
      rpc: rpcArg
    }
  },
  async ({ account, to, entrypoint, calldata, scheme, rpc }) => {
    try {
      const rpcUrl = rpc ?? DEFAULT_RPC;
      const resolved = resolveScheme(scheme ?? DEFAULT_SCHEME, true);
      const result = await executeCalls({
        rpcUrl,
        scheme: resolved,
        signerMaterial: envSigner(resolved.key),
        accountAddress: account,
        calls: [{ contractAddress: to, entrypoint, calldata }]
      });
      const receipt = await createProvider(rpcUrl).waitForTransaction(result.transactionHash);
      return ok({ scheme: resolved.key, ...result, receipt });
    } catch (error) {
      return fail(error);
    }
  }
);

server.registerTool(
  "sign_hash",
  {
    description: "Sign a transaction hash with the configured signer and return the signature felts.",
    inputSchema: { hash: z.string().describe("hash felt to sign"), scheme: schemeArg }
  },
  async ({ hash, scheme }) => {
    try {
      const resolved = resolveScheme(scheme ?? DEFAULT_SCHEME, true);
      return ok({
        scheme: resolved.key,
        signature: await resolved.signHash({ hash, signer: envSigner(resolved.key) })
      });
    } catch (error) {
      return fail(error);
    }
  }
);

server.registerTool(
  "mint",
  {
    description: "Mint STRK to an address (devnet only).",
    inputSchema: {
      address: z.string().describe("recipient address"),
      strk: z.number().int().positive().default(1000).describe("amount in whole STRK"),
      rpc: rpcArg
    }
  },
  async ({ address, strk, rpc }) => {
    try {
      await mint(rpc ?? DEFAULT_RPC, address, BigInt(strk) * 10n ** 18n);
      return ok({ minted: `${strk} STRK`, address });
    } catch (error) {
      return fail(error);
    }
  }
);

server.registerTool(
  "quickstart",
  {
    description:
      "Devnet golden path in one call: declare the scheme's account class, prefund the derived " +
      "address, deploy the account, and send one STRK transfer. Returns transaction hashes plus " +
      "the gas and fee each on-chain step consumed.",
    inputSchema: { scheme: schemeArg, rpc: rpcArg }
  },
  async ({ scheme, rpc }) => {
    try {
      const steps: string[] = [];
      const result = await quickstart({
        rpcUrl: rpc ?? DEFAULT_RPC,
        schemeKey: scheme ?? DEFAULT_SCHEME,
        log: (line) => steps.push(line)
      });
      return ok({ steps, ...result });
    } catch (error) {
      return fail(error);
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
