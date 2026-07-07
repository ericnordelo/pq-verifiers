#!/usr/bin/env node
import { Command, Option } from "commander";
import { buildCall, createAccount, createProvider } from "./starknet.js";
import { defaultRpc, parseFelt, parseFeltList, parseSignerOptions, printJson } from "./options.js";
import { listSchemes, resolveScheme } from "./schemes/registry.js";
import { resolveFunder } from "./devnet.js";
import { ensureDeclared } from "./ops/declare.js";
import { computeAccountAddress } from "./ops/deployAccount.js";
import { accountStatus } from "./ops/status.js";
import { quickstart } from "./ops/quickstart.js";
import { serveWallet } from "./serve.js";
import { walletContextFromEnv } from "./walletRpc.js";

type CommonSignerOptions = {
  scheme: string;
  privateKey?: string;
  signerCommand?: string;
  signerArg?: string[];
  falconPy?: string;
  falconKey?: string;
};

function withSchemeOptions(command: Command): Command {
  return command
    .requiredOption("--scheme <key>", "Signature scheme adapter to use, for example ecdsa-stark.")
    .option("--private-key <felt>", "Private key for a built-in Starknet.js signer adapter. Env: PQ_PRIVATE_KEY.")
    .option("--falcon-py <path>", "falcon.py checkout for the bundled Falcon signer. Env: PQ_FALCON_PY.")
    .option("--falcon-key <path>", "Key file for the bundled Falcon signer. Env: PQ_FALCON_KEY.")
    .option("--signer-command <path>", "Executable external signer for schemes not built into this CLI.")
    .option("--signer-arg <arg>", "Argument passed to --signer-command. May be repeated.", (value, previous: string[] = []) => [
      ...previous,
      value
    ]);
}

async function resolveSigner(options: CommonSignerOptions) {
  const signer = parseSignerOptions(options);
  const scheme = resolveScheme(options.scheme, signer.kind === "external-command");
  return {
    scheme,
    signerMaterial: signer,
    starknetSigner: await scheme.createStarknetSigner({ signer })
  };
}

const program = new Command();

program
  .name("pq-accounts")
  .description("Deploy and send transactions through pq-verifiers Starknet account contracts.")
  .version("0.1.0");

program
  .command("accounts")
  .description("List account contracts and signature adapters supported by this CLI.")
  .action(() => {
    printJson(
      listSchemes().map((scheme) => ({
        key: scheme.key,
        label: scheme.label,
        accountContract: scheme.accountContract,
        signatureFelts: scheme.signatureFelts,
        publicKeyFelts: scheme.publicKeyFelts,
        signerKinds: scheme.signerKinds,
        description: scheme.description
      }))
    );
  });

withSchemeOptions(program.command("public-key"))
  .description("Print the verifier public-key felts derived from the selected signer.")
  .action(async (options: CommonSignerOptions) => {
    const signer = parseSignerOptions(options);
    const scheme = resolveScheme(options.scheme, signer.kind === "external-command");
    if (!scheme.publicKey) {
      throw new Error(`scheme "${scheme.key}" does not expose public-key derivation.`);
    }
    printJson({
      scheme: scheme.key,
      publicKey: await scheme.publicKey({ signer })
    });
  });

withSchemeOptions(program.command("constructor-calldata"))
  .description(
    "Print the constructor calldata derived from the selected account signer; with " +
      "--class-hash and --salt, also the counterfactual address to prefund."
  )
  .option("--class-hash <felt>", "Declared class hash, to derive the account address.")
  .option("--salt <felt>", "Deployment salt, to derive the account address.")
  .action(async (options: CommonSignerOptions & { classHash?: string; salt?: string }) => {
    const signer = parseSignerOptions(options);
    const scheme = resolveScheme(options.scheme, signer.kind === "external-command");
    const publicKey = await scheme.publicKey({ signer });
    const constructorCalldata = scheme.constructorCalldata(publicKey);
    const address =
      options.classHash && options.salt
        ? computeAccountAddress(
            parseFelt(options.classHash, "--class-hash"),
            parseFelt(options.salt, "--salt"),
            constructorCalldata
          )
        : undefined;
    printJson({
      scheme: scheme.key,
      accountContract: scheme.accountContract,
      publicKey,
      constructorCalldata,
      address
    });
  });

withSchemeOptions(program.command("sign-hash"))
  .description("Sign a Starknet transaction hash and print the exact felts passed as tx_info.signature.")
  .requiredOption("--hash <felt>", "Transaction hash to sign.")
  .action(async (options: CommonSignerOptions & { hash: string }) => {
    const signer = parseSignerOptions(options);
    const scheme = resolveScheme(options.scheme, signer.kind === "external-command");
    const hash = parseFelt(options.hash, "--hash");
    printJson({
      scheme: scheme.key,
      hash,
      signature: await scheme.signHash({ hash, signer })
    });
  });

withSchemeOptions(program.command("execute"))
  .description("Send an invoke transaction from an account address using the selected signature adapter.")
  .option("--rpc <url>", "Starknet JSON-RPC endpoint. Env: PQ_RPC.", defaultRpc())
  .requiredOption("--account <address>", "Account contract address that will pay and validate the transaction.")
  .requiredOption("--to <address>", "Target contract address for the call.")
  .requiredOption("--entrypoint <name>", "Target entrypoint selector name.")
  .option("--calldata <felt...>", "Call calldata as repeated values or comma-separated felt lists.", [])
  .option("--nonce <felt>", "Override account nonce.")
  .option("--version <felt>", "Override transaction version. Starknet.js v10 supports 0x3 account transactions.")
  .addOption(new Option("--cairo-version <version>", "Account Cairo version.").choices(["0", "1"]))
  .action(
    async (
      options: CommonSignerOptions & {
        rpc: string;
        account: string;
        to: string;
        entrypoint: string;
        calldata?: string[];
        nonce?: string;
        version?: string;
        cairoVersion?: "0" | "1";
      }
    ) => {
      const { scheme, signerMaterial, starknetSigner } = await resolveSigner(options);
      const account = await createAccount({
        rpcUrl: options.rpc,
        accountAddress: parseFelt(options.account, "--account"),
        scheme,
        signer: starknetSigner,
        cairoVersion: options.cairoVersion,
        transactionVersion: options.version ? parseFelt(options.version, "--version") : undefined
      });
      const call = buildCall(
        parseFelt(options.to, "--to"),
        options.entrypoint,
        parseFeltList(options.calldata, "--calldata")
      );
      const response = await account.execute([call], {
        nonce: options.nonce ? parseFelt(options.nonce, "--nonce") : undefined,
        version: options.version ? parseFelt(options.version, "--version") : undefined,
        // Fee estimation must run the verifier: a SKIP_VALIDATE estimate would
        // under-provision l2 gas for validation-heavy accounts.
        skipValidate: false
      });
      printJson({ scheme: scheme.key, transactionHash: response.transaction_hash, response });
    }
  );

withSchemeOptions(program.command("deploy-account"))
  .description("Deploy an account contract with Starknet.js deployAccount and the selected signature adapter.")
  .option("--rpc <url>", "Starknet JSON-RPC endpoint. Env: PQ_RPC.", defaultRpc())
  .requiredOption("--class-hash <felt>", "Declared account class hash.")
  .option("--address-salt <felt>", "Deployment salt. Defaults to 0.", "0")
  .option("--constructor-calldata <felt...>", "Constructor calldata as repeated values or comma-separated felt lists.", [])
  .option("--contract-address <felt>", "Precomputed account address override.")
  .option("--version <felt>", "Override transaction version. Starknet.js v10 supports 0x3 account transactions.")
  .addOption(new Option("--cairo-version <version>", "Account Cairo version.").choices(["0", "1"]))
  .action(
    async (
      options: CommonSignerOptions & {
        rpc: string;
        classHash: string;
        addressSalt: string;
        constructorCalldata?: string[];
        contractAddress?: string;
        version?: string;
        cairoVersion?: "0" | "1";
      }
    ) => {
      const { scheme, signerMaterial, starknetSigner } = await resolveSigner(options);
      const accountAddress = options.contractAddress
        ? parseFelt(options.contractAddress, "--contract-address")
        : "0x0";
      const account = await createAccount({
        rpcUrl: options.rpc,
        accountAddress,
        scheme,
        signer: starknetSigner,
        cairoVersion: options.cairoVersion,
        transactionVersion: options.version ? parseFelt(options.version, "--version") : undefined
      });
      const explicitConstructorCalldata = parseFeltList(
        options.constructorCalldata,
        "--constructor-calldata"
      );
      const derivedPublicKey = explicitConstructorCalldata.length === 0
        ? await scheme.publicKey({ signer: signerMaterial })
        : [];
      const constructorCalldata = explicitConstructorCalldata.length === 0
        ? scheme.constructorCalldata(derivedPublicKey)
        : explicitConstructorCalldata;
      const response = await account.deployAccount(
        {
          classHash: parseFelt(options.classHash, "--class-hash"),
          addressSalt: parseFelt(options.addressSalt, "--address-salt"),
          constructorCalldata,
          contractAddress: options.contractAddress ? parseFelt(options.contractAddress, "--contract-address") : undefined
        },
        {
          version: options.version ? parseFelt(options.version, "--version") : undefined,
          // Fee estimation must run the verifier: a SKIP_VALIDATE estimate would
          // under-provision l2 gas for validation-heavy accounts.
          skipValidate: false
        }
      );
      printJson({
        scheme: scheme.key,
        accountContract: scheme.accountContract,
        constructorCalldata,
        publicKey: derivedPublicKey.length === 0 ? undefined : derivedPublicKey,
        transactionHash: response.transaction_hash,
        response
      });
    }
  );

program
  .command("declare")
  .description("Declare an account class using a funded account (devnet predeployed by default).")
  .option("--rpc <url>", "Starknet JSON-RPC endpoint. Env: PQ_RPC.", defaultRpc())
  .option("--scheme <key>", "Scheme whose account contract to declare.")
  .option("--contract <name>", "Contract name to declare instead of deriving it from --scheme.")
  .option("--funder-address <felt>", "Funded account address paying the declaration. Env: PQ_FUNDER_ADDRESS.")
  .option("--funder-private-key <felt>", "Funded account private key. Env: PQ_FUNDER_PRIVATE_KEY.")
  .action(
    async (options: {
      rpc: string;
      scheme?: string;
      contract?: string;
      funderAddress?: string;
      funderPrivateKey?: string;
    }) => {
      const contractName = options.contract ?? (options.scheme ? resolveScheme(options.scheme, true).accountContract : undefined);
      if (!contractName) {
        throw new Error("Provide --scheme or --contract.");
      }
      const funder = await resolveFunder(options.rpc, {
        address: options.funderAddress,
        privateKey: options.funderPrivateKey
      });
      const result = await ensureDeclared({
        provider: createProvider(options.rpc),
        funderAddress: funder.address,
        funderPrivateKey: funder.privateKey,
        contractName
      });
      printJson(result);
    }
  );

program
  .command("status")
  .description("Report deployment state, nonce, and STRK balance for an account address.")
  .option("--rpc <url>", "Starknet JSON-RPC endpoint. Env: PQ_RPC.", defaultRpc())
  .requiredOption("--address <felt>", "Account address to inspect.")
  .action(async (options: { rpc: string; address: string }) => {
    printJson(await accountStatus(createProvider(options.rpc), parseFelt(options.address, "--address")));
  });

program
  .command("quickstart")
  .description(
    "Devnet golden path: declare the account class, prefund the derived address, deploy, and send one transfer."
  )
  .option("--rpc <url>", "Devnet JSON-RPC endpoint. Env: PQ_RPC.", defaultRpc())
  .option("--scheme <key>", "Scheme to demonstrate.", "falcon-512-shake")
  .option("--salt <felt>", "Deployment salt. Defaults to a random value.")
  .option("--falcon-py <path>", "falcon.py checkout for the bundled Falcon signer. Env: PQ_FALCON_PY.")
  .option("--falcon-key <path>", "Key file overriding the committed demo key. Env: PQ_FALCON_KEY.")
  .action(async (options: { rpc: string; scheme: string; salt?: string; falconPy?: string; falconKey?: string }) => {
    if (options.falconPy) {
      process.env.PQ_FALCON_PY = options.falconPy;
    }
    if (options.falconKey) {
      process.env.PQ_FALCON_KEY = options.falconKey;
    }
    const result = await quickstart({
      rpcUrl: options.rpc,
      schemeKey: options.scheme,
      salt: options.salt ? parseFelt(options.salt, "--salt") : undefined,
      log: (line) => process.stderr.write(`* ${line}\n`)
    });
    process.stderr.write("\n");
    printJson(result);
    process.stderr.write(
      `\nAccount ${result.address} is live. Send another transaction with:\n` +
        `  pq-accounts execute --rpc <rpc> --scheme ${result.scheme} ` +
        `--account ${result.address} --to <target> --entrypoint <name> --calldata <felts...>\n`
    );
  });

withSchemeOptions(program.command("serve"))
  .description(
    "Run the local wallet daemon for browser dapps: injects a get-starknet-discoverable " +
      "wallet that signs with the selected scheme through this process."
  )
  .option("--rpc <url>", "Starknet JSON-RPC endpoint. Env: PQ_RPC.", defaultRpc())
  .option("--account <address>", "Deployed account address the wallet exposes. Env: PQ_ACCOUNT.", process.env.PQ_ACCOUNT)
  .option("--port <number>", "Port to listen on (127.0.0.1 only).", "8777")
  .option(
    "--wallet-id <id>",
    "Injected window.starknet_<id> key. StarknetKit dapps (Voyager) only show ids in " +
      "their connector list; the default occupies a registered-but-absent slot.",
    "braavos"
  )
  .action(
    async (
      options: CommonSignerOptions & {
        rpc: string;
        account?: string;
        port: string;
        walletId: string;
      }
    ) => {
      if (!options.account) {
        throw new Error("Provide the deployed account with --account or PQ_ACCOUNT.");
      }
      const signerMaterial = parseSignerOptions(options);
      const ctx = walletContextFromEnv({
        rpcUrl: options.rpc,
        accountAddress: parseFelt(options.account, "--account"),
        schemeKey: options.scheme,
        signerMaterial,
        warn: (line) => process.stderr.write(`  ! ${line}\n`)
      });
      serveWallet({
        ctx,
        port: Number(options.port),
        walletId: options.walletId,
        log: (line) => process.stderr.write(`${line}\n`)
      });
      // The server keeps the process alive; commander returns here.
    }
  );

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`pq-accounts: ${message}\n`);
  process.exitCode = 1;
});
