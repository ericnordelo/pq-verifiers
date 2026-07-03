#!/usr/bin/env node
import { Command, Option } from "commander";
import { buildCall, createAccount } from "./starknet.js";
import { parseFelt, parseFeltList, parseSignerOptions, printJson } from "./options.js";
import { listSchemes, resolveScheme } from "./schemes/registry.js";

type CommonSignerOptions = {
  scheme: string;
  privateKey?: string;
  signerCommand?: string;
  signerArg?: string[];
};

function withSchemeOptions(command: Command): Command {
  return command
    .requiredOption("--scheme <key>", "Signature scheme adapter to use, for example ecdsa-stark.")
    .option("--private-key <felt>", "Private key for a built-in Starknet.js signer adapter.")
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
  .description("Print the constructor calldata derived from the selected account signer.")
  .action(async (options: CommonSignerOptions) => {
    const signer = parseSignerOptions(options);
    const scheme = resolveScheme(options.scheme, signer.kind === "external-command");
    const publicKey = await scheme.publicKey({ signer });
    printJson({
      scheme: scheme.key,
      accountContract: scheme.accountContract,
      publicKey,
      constructorCalldata: scheme.constructorCalldata(publicKey)
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
  .requiredOption("--rpc <url>", "Starknet JSON-RPC endpoint.")
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
        version: options.version ? parseFelt(options.version, "--version") : undefined
      });
      printJson({ scheme: scheme.key, transactionHash: response.transaction_hash, response });
    }
  );

withSchemeOptions(program.command("deploy-account"))
  .description("Deploy an account contract with Starknet.js deployAccount and the selected signature adapter.")
  .requiredOption("--rpc <url>", "Starknet JSON-RPC endpoint.")
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
          version: options.version ? parseFelt(options.version, "--version") : undefined
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

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`pq-accounts: ${message}\n`);
  process.exitCode = 1;
});
