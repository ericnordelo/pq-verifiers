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

export function parseSignerOptions(options: { privateKey?: string; signerCommand?: string; signerArg?: string[] }): SignerMaterial {
  if (options.privateKey && options.signerCommand) {
    throw new Error("Use either --private-key or --signer-command, not both.");
  }
  if (options.privateKey) {
    return {
      kind: "private-key",
      privateKey: parseFelt(options.privateKey, "--private-key")
    };
  }
  if (options.signerCommand) {
    return {
      kind: "external-command",
      command: options.signerCommand,
      args: options.signerArg ?? []
    };
  }
  throw new Error("Provide signing material with --private-key or --signer-command.");
}

export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

