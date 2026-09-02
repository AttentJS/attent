/**
 * Custom PolicyEvaluator example (§16): the built-in evaluator already
 * understands numeric ceilings (`maxAmount`/`minAmount`, §6/policy/default.ts)
 * via a capability's own `constraints` — this example shows the *extension
 * point* itself by adding a business-hours predicate the default evaluator
 * doesn't know about, composed on top of (not instead of) the default
 * amount-ceiling check. Run:
 *
 *   npm run example:authorization
 */
import {
  generateKeyProvider,
  createIdentity,
  issueCredential,
  rootChain,
  authorize,
  memoryRevocationStore,
  defaultPolicyEvaluator,
} from "../../src/index.js";
import type { PolicyEvaluator, PolicyEvaluatorInput } from "../../src/index.js";

/**
 * Wraps the default evaluator: still enforces `maxAmount`/`minAmount` (and
 * any other constraint the default evaluator understands), then additionally
 * rejects if the capability carries `businessHoursOnly: true` and
 * `context.hour` falls outside 9-17. A `PolicyEvaluator` must never throw —
 * an out-of-range/missing `hour` is treated as a deny, not an error.
 */
function businessHoursPolicyEvaluator(): PolicyEvaluator {
  const base = defaultPolicyEvaluator();
  return {
    name: "business-hours",
    evaluate(input: PolicyEvaluatorInput): boolean {
      const { businessHoursOnly, ...rest } = input.capability.constraints ?? {};
      // Delegate everything the default evaluator already understands (e.g.
      // maxAmount/minAmount) to it, minus the custom key it would otherwise
      // treat as an unrecognized strict-equality constraint against context.
      if (!base.evaluate({ ...input, capability: { ...input.capability, constraints: rest } })) {
        return false;
      }
      if (businessHoursOnly !== true) {
        return true;
      }
      const hour = input.context.hour;
      return typeof hour === "number" && hour >= 9 && hour < 17;
    },
  };
}

async function main(): Promise<void> {
  const rootKeys = await generateKeyProvider();
  const root = createIdentity({ kind: "application", name: "acme-app", publicJWK: await rootKeys.getPublicJWK() });

  const agentKeys = await generateKeyProvider();
  const agent = createIdentity({
    kind: "agent",
    name: "support-agent",
    createdBy: root.id,
    publicJWK: await agentKeys.getPublicJWK(),
  });

  const credential = await issueCredential({
    issuer: root,
    subject: agent,
    keyProvider: rootKeys,
    capabilities: [
      {
        action: "refunds:create",
        resource: "order:*",
        constraints: { maxAmount: 50, businessHoursOnly: true },
      },
    ],
    aud: "order:*",
    ttlSeconds: 900,
  });
  const chain = rootChain(credential);

  const store = memoryRevocationStore();
  const policyEvaluator = businessHoursPolicyEvaluator();

  const withinHoursAndAmount = await authorize(
    { credential: chain, action: "refunds:create", resource: "order:1", context: { amount: 20, hour: 10 } },
    { revocationStore: store, policyEvaluator }
  );
  console.log("within business hours, within ceiling:", withinHoursAndAmount);

  const outsideHours = await authorize(
    { credential: chain, action: "refunds:create", resource: "order:1", context: { amount: 20, hour: 22 } },
    { revocationStore: store, policyEvaluator }
  );
  console.log("outside business hours:", outsideHours);

  const overCeiling = await authorize(
    { credential: chain, action: "refunds:create", resource: "order:1", context: { amount: 100, hour: 10 } },
    { revocationStore: store, policyEvaluator }
  );
  console.log("within business hours, over ceiling:", overCeiling);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
