// SPDX-License-Identifier: Apache-2.0
/**
 * Outcome confirmations. A receipt proves what the issuer claimed; a
 * confirmation proves what happened, observed in a system the issuer does
 * not control and linked by capsule digest. Levels: W0 asserted by the
 * issuer, W1 observed by a Hivemind connector through the source's API,
 * W2 signed by the source itself (anyone can check without trusting
 * Hivemind), W3 a quorum / web proof / attested enclave. Confirmations are
 * ordinary SCITT statements and register like everything else.
 * AI-judge opinions are modelled separately (`opinion` kind) and are never
 * confirmations and never the sole basis for billing.
 */
import { cborDecode, cborEncode, cborToPlain } from '../core/cbor.js';
import { coseSign1, parseSign1, verifySign1 } from '../core/cose.js';
import { digestOf, type Digest } from '../core/capsule.js';
import { celVerdict, CelDuration, CelTimestamp, parseTimestamp, type CelValue } from '../core/cel.js';
import type { ReceiptSigner } from '../core/keys.js';
import type { KeyObject } from 'node:crypto';

export const CONFIRMATION_PROFILE_URI = 'urn:hivemind:receipts:confirmation:1';
export const CONFIRMATION_MEDIA_TYPE = 'application/vnd.hivemind.confirmation+cbor';
export const CRITERIA_PROFILE_URI = 'urn:hivemind:receipts:criteria:1';
export const CRITERIA_MEDIA_TYPE = 'application/vnd.hivemind.criteria+cbor';
export const VERDICT_MEDIA_TYPE = 'application/vnd.hivemind.criteria-verdict+cbor';
export const OPINION_MEDIA_TYPE = 'application/vnd.hivemind.opinion+cbor';

export type ConfirmationLevel = 'W0' | 'W1' | 'W2' | 'W3';

export interface ConfirmationPayload {
  profile: typeof CONFIRMATION_PROFILE_URI;
  capsule_id: Digest;
  source: { system: string; account_commitment?: Digest };
  observation: {
    event: string;
    object_id?: string;
    state: string;
    at: string; // ISO time the source reports
    fields?: Record<string, string | number | boolean>;
  };
  evidence: { kind: string; digest: Digest; detail?: string };
  level: ConfirmationLevel;
  witness: string;
}

export async function signConfirmation(
  signer: ReceiptSigner,
  payload: ConfirmationPayload,
): Promise<Buffer> {
  return coseSign1(signer, cborEncode(payload as never), {
    contentType: CONFIRMATION_MEDIA_TYPE,
    cwt: { iss: payload.witness, sub: payload.capsule_id, iat: Math.floor(Date.parse(payload.observation.at) / 1000) || 0 },
  });
}

export function parseConfirmation(bytes: Uint8Array): ConfirmationPayload {
  const p = parseSign1(Buffer.from(bytes));
  if (!p.payload) throw new Error('confirmation payload missing');
  const plain = cborToPlain(cborDecode(p.payload)) as ConfirmationPayload;
  if (plain.profile !== CONFIRMATION_PROFILE_URI) throw new Error('bad confirmation profile');
  return plain;
}

export interface CriteriaPayload {
  profile: typeof CRITERIA_PROFILE_URI;
  program: string;
  template_id?: string;
  description?: string;
}

export function criteriaDigest(program: string, templateId?: string): Digest {
  return digestOf(cborEncode({
    profile: CRITERIA_PROFILE_URI, program, ...(templateId ? { template_id: templateId } : {}),
  } as never));
}

export async function signCriteria(signer: ReceiptSigner, payload: CriteriaPayload): Promise<Buffer> {
  return coseSign1(signer, cborEncode(payload as never), { contentType: CRITERIA_MEDIA_TYPE });
}

export interface VerdictPayload {
  profile: 'urn:hivemind:receipts:criteria-verdict:1';
  capsule_id: Digest;
  criteria_ref: Digest;
  verdict: boolean;
  confirmation_digests: Digest[];
  evaluated_at: string;
}

export async function signVerdict(signer: ReceiptSigner, payload: VerdictPayload): Promise<Buffer> {
  return coseSign1(signer, cborEncode(payload as never), { contentType: VERDICT_MEDIA_TYPE });
}

/**
 * Build the CEL environment from confirmations: env[system] holds the latest
 * observation (state + fields + at timestamp). Timeline helpers
 * (`reopened_within`, `held_for`, `state_was`) read the confirmation history,
 * so criteria stay one deterministic program any verifier can re-run.
 */
export function evaluateCriteria(input: {
  program: string;
  confirmations: ConfirmationPayload[];
  subjectName?: string;
  extraEnv?: Record<string, CelValue>;
}): { verdict: boolean; env: Record<string, CelValue> } {
  const bySystem = new Map<string, ConfirmationPayload[]>();
  for (const c of input.confirmations) {
    const list = bySystem.get(c.source.system) ?? [];
    list.push(c);
    bySystem.set(c.source.system, list);
  }
  const env: Record<string, CelValue> = { ...(input.extraEnv ?? {}) };
  for (const [system, list] of bySystem) {
    const sorted = [...list].sort((a, b) => a.observation.at.localeCompare(b.observation.at));
    const latest = sorted[sorted.length - 1]!;
    const obj: Record<string, CelValue> = {
      state: latest.observation.state,
      event: latest.observation.event,
      ...(latest.observation.object_id ? { object_id: latest.observation.object_id } : {}),
      at: parseTimestamp(latest.observation.at),
      ...((latest.observation.fields ?? {}) as Record<string, CelValue>),
    };
    env[system] = obj;
    if (input.subjectName) env[input.subjectName] = obj;
  }
  const timeline = (window: CelDuration, predicate: (c: ConfirmationPayload) => boolean, afterState?: string): boolean => {
    for (const list of bySystem.values()) {
      const sorted = [...list].sort((a, b) => a.observation.at.localeCompare(b.observation.at));
      let anchor: CelTimestamp | null = null;
      for (const c of sorted) {
        if (afterState && c.observation.state === afterState && !anchor)
          anchor = parseTimestamp(c.observation.at);
        if (anchor && predicate(c)) {
          const t = parseTimestamp(c.observation.at).epochSeconds;
          if (t > anchor.epochSeconds && t - anchor.epochSeconds <= window.seconds) return true;
        }
      }
    }
    return false;
  };
  const verdict = celVerdict(input.program, env, {
    reopened_within: (args) =>
      args[0] instanceof CelDuration &&
      timeline(args[0], (c) => c.observation.state === 'reopened' || c.observation.event === 'reopened', 'solved'),
    reverted_within: (args) =>
      args[0] instanceof CelDuration &&
      timeline(args[0], (c) => c.observation.state === 'reverted' || c.observation.event === 'reverted', 'merged'),
    state_was: (args) => input.confirmations.some((c) => c.observation.state === String(args[0])),
    held_for: (args) => {
      if (!(args[1] instanceof CelDuration)) return false;
      const state = String(args[0]);
      const now = args[2] instanceof CelTimestamp ? args[2].epochSeconds : Date.now() / 1000;
      const first = input.confirmations
        .filter((c) => c.observation.state === state)
        .sort((a, b) => a.observation.at.localeCompare(b.observation.at))[0];
      if (!first) return false;
      const stillThere = ![...bySystem.values()].some((list) => {
        const sorted = [...list].sort((a, b) => a.observation.at.localeCompare(b.observation.at));
        const firstIdx = sorted.findIndex((c) => c.observation.state === state);
        return firstIdx >= 0 && sorted.slice(firstIdx + 1).some((c) => c.observation.state !== state);
      });
      return stillThere && now - parseTimestamp(first.observation.at).epochSeconds >= args[1].seconds;
    },
  });
  return { verdict, env };
}

/** Verify a signed verdict by re-running the program — billing is reproducible. */
export function reverifyVerdict(input: {
  verdictStatement: Buffer;
  evaluatorKey: KeyObject;
  program: string;
  confirmations: ConfirmationPayload[];
  subjectName?: string;
}): { signature: boolean; reproduced: boolean; verdict: boolean } {
  const parsed = parseSign1(input.verdictStatement);
  const signature = verifySign1(parsed, input.evaluatorKey);
  const payload = cborToPlain(cborDecode(parsed.payload!)) as unknown as VerdictPayload;
  const again = evaluateCriteria({
    program: input.program,
    confirmations: input.confirmations,
    ...(input.subjectName ? { subjectName: input.subjectName } : {}),
  });
  return { signature, reproduced: again.verdict === payload.verdict, verdict: payload.verdict };
}

export interface OpinionPayload {
  profile: 'urn:hivemind:receipts:opinion:1';
  capsule_id: Digest;
  opinion: 'supports' | 'disputes' | 'abstains';
  method_digest: Digest;
  judge: { kind: 'human' | 'service' | 'ai'; model_id?: string; model_version?: string };
  rationale_commitment?: Digest;
}

export async function signOpinion(signer: ReceiptSigner, payload: OpinionPayload): Promise<Buffer> {
  return coseSign1(signer, cborEncode(payload as never), { contentType: OPINION_MEDIA_TYPE });
}

export const CRITERIA_TEMPLATES: Record<string, { program: string; description: string; subject: string }> = {
  'ticket-resolved': {
    subject: 'ticket',
    description: 'Ticket solved and not reopened within 7 days',
    program: "ticket.state == 'solved' && !reopened_within(duration('168h'))",
  },
  'pr-merged-green': {
    subject: 'pr',
    description: 'PR merged with green CI and no revert within 7 days',
    program: "pr.state == 'merged' && pr.ci == 'success' && !reverted_within(duration('168h'))",
  },
  'invoice-processed': {
    subject: 'invoice',
    description: 'E-invoice delivered and accepted by the network',
    program: "invoice.state == 'accepted'",
  },
  'meeting-held': {
    subject: 'meeting',
    description: 'Meeting held with the expected attendees present',
    program: "meeting.state == 'held' && meeting.attendees_present >= meeting.attendees_expected",
  },
  'payment-collected': {
    subject: 'payment',
    description: 'Payment succeeded and credited, no dispute opened',
    program: "payment.state == 'succeeded' && !state_was('disputed')",
  },
  'document-signed': {
    subject: 'document',
    description: 'Document signed by all required parties',
    program: "document.state == 'signed' && document.signatures >= document.required_signatures",
  },
  'refund-issued': {
    subject: 'refund',
    description: 'Refund issued for at least the agreed amount',
    program: "refund.state == 'issued'",
  },
};

export * from './dsse.js';
export * from './gitsign.js';
export { validateFatturaPA, validatePeppolBis3, verifyXmlSignature, type SchemaValidationResult, type XmlSigResult } from './xmldsig.js';
