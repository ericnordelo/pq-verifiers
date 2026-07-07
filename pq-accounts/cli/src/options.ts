import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";
import type { Felt, SignerMaterial } from "./schemes/types.js";

const feltSchema = z.string().min(1).regex(/^(0x[0-9a-fA-F]+|[0-9]+)$/, "expected a decimal or 0x-prefixed felt");

export function parseFelt(value: string, label: string): Felt {
  const parsed = feltSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error(`${label}: ${parsed.error.issues[0]?.message ?? "invalid felt"}`);
  }
  return parsed.data;
}

export function parseFeltList(values: string[] | undefined, label: string): Felt[] {
  return (values ?? []).flatMap((value) =>
    value
      .split(",")
      .filter((part) => part.length > 0)
      .map((part) => parseFelt(part.trim(), label))
  );
}

/** Flags and environment variables that select signing material. */
export type SignerOptions = {
  privateKey?: string;
  signerCommand?: string;
  signerArg?: string[];
  falconPy?: string;
  falconKey?: string;
};

/** Path to the bundled Falcon Python signer, resolved relative to this package. */
export function falconSignerScript(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "signers", "falcon-python", "falcon_signer.py");
}

/** Path to the committed demo key (INSECURE: its private material is public). */
export function demoKeyPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "signers", "falcon-python", "demo-key.json");
}

/** Builds the external-signer material for the bundled Falcon signer. */
export function falconSignerMaterial(falconPy: string, keyFile: string): SignerMaterial {
  return {
    kind: "external-command",
    command: process.env.PQ_PYTHON ?? "python3",
    args: [falconSignerScript(), "--falcon-py", falconPy, "--key", keyFile]
  };
}

/** Resolves signing material from flags, falling back to PQ_* environment variables.
 * Precedence: --signer-command > --private-key (or PQ_PRIVATE_KEY) > the bundled
 * Falcon signer via --falcon-py/--falcon-key (or PQ_FALCON_PY/PQ_FALCON_KEY). */
export function parseSignerOptions(options: SignerOptions): SignerMaterial {
  if (options.privateKey && options.signerCommand) {
    throw new Error("Use either --private-key or --signer-command, not both.");
  }
  if (options.signerCommand) {
    return {
      kind: "external-command",
      command: options.signerCommand,
      args: options.signerArg ?? []
    };
  }
  const privateKey = options.privateKey ?? process.env.PQ_PRIVATE_KEY;
  if (privateKey) {
    return {
      kind: "private-key",
      privateKey: parseFelt(privateKey, "--private-key")
    };
  }
  const falconPy = options.falconPy ?? process.env.PQ_FALCON_PY;
  const falconKey = options.falconKey ?? process.env.PQ_FALCON_KEY;
  if (falconPy && falconKey) {
    return falconSignerMaterial(falconPy, falconKey);
  }
  if (falconPy || falconKey) {
    throw new Error(
      "The bundled Falcon signer needs both a falcon.py checkout (--falcon-py or PQ_FALCON_PY) " +
        "and a key file (--falcon-key or PQ_FALCON_KEY)."
    );
  }
  throw new Error(
    "Provide signing material: --private-key for ecdsa-stark, --falcon-py and --falcon-key " +
      "for the Falcon schemes, or --signer-command for a custom external signer."
  );
}

export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

