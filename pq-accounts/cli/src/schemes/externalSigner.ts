import { spawn } from "node:child_process";
import type {
  CreateStarknetSignerInput,
  ExternalSignerRequest,
  Felt,
  SignerMaterial
} from "./types.js";

type ExternalResult = {
  signature?: Felt[];
  publicKey?: Felt[];
};

function assertExternalSigner(material: SignerMaterial): asserts material is Extract<SignerMaterial, { kind: "external-command" }> {
  if (material.kind !== "external-command") {
    throw new Error("This scheme expects --signer-command instead of --private-key.");
  }
}

export async function runExternalSigner(material: SignerMaterial, request: ExternalSignerRequest): Promise<ExternalResult> {
  assertExternalSigner(material);

  return new Promise((resolve, reject) => {
    const child = spawn(material.command, material.args, {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`external signer exited with code ${code}: ${stderr.trim()}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout) as ExternalResult);
      } catch (error) {
        reject(new Error(`external signer returned invalid JSON: ${(error as Error).message}`));
      }
    });

    child.stdin.end(`${JSON.stringify(request)}\n`);
  });
}

export class ExternalCommandStarknetSigner {
  constructor(
    private readonly scheme: string,
    private readonly input: CreateStarknetSignerInput
  ) {}

  async signTransaction(calls: unknown, details: unknown): Promise<Felt[]> {
    const result = await runExternalSigner(this.input.signer, {
      scheme: this.scheme,
      action: "sign-transaction",
      payload: { calls, details }
    });
    if (!result.signature) {
      throw new Error("external signer response must include a signature array.");
    }
    return result.signature;
  }

  async signDeployAccountTransaction(details: unknown): Promise<Felt[]> {
    const result = await runExternalSigner(this.input.signer, {
      scheme: this.scheme,
      action: "sign-deploy-account",
      payload: { details }
    });
    if (!result.signature) {
      throw new Error("external signer response must include a signature array.");
    }
    return result.signature;
  }

  async signDeclareTransaction(): Promise<Felt[]> {
    throw new Error("declare transactions are not supported by this CLI signer.");
  }

  async signMessage(): Promise<Felt[]> {
    throw new Error("typed-data signing is not supported by this CLI signer.");
  }
}

