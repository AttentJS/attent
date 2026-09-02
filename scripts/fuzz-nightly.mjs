import { spawnSync } from "node:child_process";

// CI runs the fuzz suite at a fixed, modest numRuns for fast reproducible
// feedback; this script runs the same suite much longer for deeper local
// exploration, without needing a shell-specific env-var syntax (works
// identically on POSIX shells and PowerShell/cmd).
const env = { ...process.env, FC_NUM_RUNS: process.env.FC_NUM_RUNS ?? "5000" };

const result = spawnSync(
  "npx",
  ["vitest", "run", "tests/property", "tests/delegation/narrow.property.test.ts"],
  { stdio: "inherit", env, shell: true }
);

process.exit(result.status ?? 1);
