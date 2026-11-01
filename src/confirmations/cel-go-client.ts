// SPDX-License-Identifier: Apache-2.0
/**
 * Client for the cel-go reference evaluator service
 * (services/criteria-evaluator). On the billing path, verdicts come from
 * reference CEL — the in-repo subset remains for client-side previews and
 * offline replay cross-checks, and disagreements fail closed here.
 */
import type { ConfirmationPayload } from './confirmation.js';
import { evaluateCriteria } from './confirmation.js';

export class CelGoEvaluator {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchFn: typeof fetch = fetch,
  ) {}

  async evaluateReference(input: {
    program: string;
    confirmations: ConfirmationPayload[];
    subjectName?: string;
    requireAgreementWithSubset?: boolean;
  }): Promise<{ verdict: boolean; engine: 'cel-go'; subsetAgrees: boolean }> {
    const subset = evaluateCriteria(input);
    const timeline = input.confirmations.map((c) => ({
      state: c.observation.state,
      event: c.observation.event,
      at: c.observation.at,
    }));
    const env: Record<string, unknown> = {};
    // Build the same env shape the subset builds (latest per system).
    const bySystem = new Map<string, ConfirmationPayload>();
    for (const c of input.confirmations) bySystem.set(c.source.system, c);
    for (const [system, c] of bySystem) {
      const obj: Record<string, unknown> = {
        state: c.observation.state,
        event: c.observation.event,
        ...(c.observation.fields ?? {}),
      };
      env[system] = obj;
      if (input.subjectName) env[input.subjectName] = obj;
    }
    const res = await this.fetchFn(`${this.baseUrl.replace(/\/$/, '')}/evaluate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        program: input.program,
        env,
        timeline: { confirmations: timeline, now: new Date().toISOString() },
      }),
    });
    if (!res.ok) throw new Error(`cel-go evaluator answered ${res.status}: ${await res.text().catch(() => '')}`);
    const { verdict } = (await res.json()) as { verdict: boolean };
    const subsetAgrees = verdict === subset.verdict;
    if (input.requireAgreementWithSubset && !subsetAgrees) {
      throw new Error(
        `CEL disagreement: reference cel-go says ${verdict}, subset says ${subset.verdict} - refusing to bill on a divergent verdict`,
      );
    }
    return { verdict, engine: 'cel-go', subsetAgrees };
  }
}
