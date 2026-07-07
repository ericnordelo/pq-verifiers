import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { hash, type CompiledSierra, type CompiledSierraCasm } from "starknet";

/** A built contract class pair (Sierra + CASM) ready for declaration. */
export type ContractArtifacts = {
  contractName: string;
  sierra: CompiledSierra;
  casm: CompiledSierraCasm;
  classHash: string;
};

/** Directories that may hold the scarb build output: the contracts package belongs to
 * the repository workspace, so artifacts land in the workspace-root target; a local
 * target is also checked in case the package is built standalone. */
function contractsTargetDirs(): string[] {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // src/ during tsx runs, dist/ after tsc — both sit directly under cli/.
  const pqAccounts = path.resolve(here, "..", "..");
  return [
    path.join(pqAccounts, "..", "target", "dev"),
    path.join(pqAccounts, "contracts", "target", "dev")
  ];
}

/** Loads the built class files for an account contract and computes its class hash. */
export function loadContractArtifacts(contractName: string): ContractArtifacts {
  for (const dir of contractsTargetDirs()) {
    const sierraPath = path.join(dir, `pq_accounts_${contractName}.contract_class.json`);
    const casmPath = path.join(dir, `pq_accounts_${contractName}.compiled_contract_class.json`);
    let sierra: CompiledSierra;
    let casm: CompiledSierraCasm;
    try {
      sierra = JSON.parse(readFileSync(sierraPath, "utf8")) as CompiledSierra;
      casm = JSON.parse(readFileSync(casmPath, "utf8")) as CompiledSierraCasm;
    } catch {
      continue;
    }
    return {
      contractName,
      sierra,
      casm,
      classHash: hash.computeContractClassHash(sierra)
    };
  }
  throw new Error(
    `missing build artifacts for ${contractName}. Run "scarb build" in pq-accounts/contracts first.`
  );
}
