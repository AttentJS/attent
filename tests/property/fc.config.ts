/**
 * Shared fast-check run parameters (§17/§21 Phase 7 acceptance). CI runs
 * every property test with fast-check's own default fixed seed behavior
 * (deterministic unless overridden) at a modest `numRuns` for fast feedback.
 * `npm run test:property:nightly` sets `FC_NUM_RUNS`/`FC_SEED` to run the
 * same suite much longer / with a random seed for deeper exploration,
 * without editing any individual test file.
 */
export function fcParams(defaultNumRuns: number): { numRuns: number; seed?: number } {
  const numRuns = process.env.FC_NUM_RUNS ? Number(process.env.FC_NUM_RUNS) : defaultNumRuns;
  const seed = process.env.FC_SEED ? Number(process.env.FC_SEED) : undefined;
  return seed !== undefined ? { numRuns, seed } : { numRuns };
}
