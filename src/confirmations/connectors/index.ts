// SPDX-License-Identifier: Apache-2.0
/**
 * Confirmation connectors. Each one observes a source system through its API
 * or its signed webhooks and returns an observation + evidence digest; the
 * confirmation statement is then signed by the connector's witness key (W1),
 * or by the source's own signature where the platform provides one (W2).
 * All network access is injectable so connectors run in egress-restricted
 * workers and under test fakes. Secrets never leave the worker.
 */
import { createHash, createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify, createVerify } from 'node:crypto';
import { cborEncode } from '../../core/cbor.js';
import { digestOf, type Digest } from '../../core/capsule.js';
import type { ConfirmationLevel, ConfirmationPayload } from '../confirmation.js';
import { verifyPgpSignature, type PgpPublicKey, type PgpVerifyResult } from '../openpgp.js';
import { validateFatturaPA, validatePeppolBis3, verifyXmlSignature, type SchemaValidationResult } from '../xmldsig.js';

export { validateFatturaPA, validatePeppolBis3, verifyXmlSignature, type SchemaValidationResult };
export * from '../dsse.js';
export * from '../gitsign.js';

export type FetchFn = typeof fetch;

export interface Observation {
  system: string;
  event: string;
  objectId?: string | undefined;
  state: string;
  at: string;
  fields?: Record<string, string | number | boolean>;
  evidenceKind: string;
  evidenceDigest: Digest;
  level: ConfirmationLevel;
  accountCommitment?: Digest;
}

export function toConfirmation(obs: Observation, capsuleId: Digest, witness: string): ConfirmationPayload {
  return {
    profile: 'urn:hivemind:receipts:confirmation:1',
    capsule_id: capsuleId,
    source: {
      system: obs.system,
      ...(obs.accountCommitment ? { account_commitment: obs.accountCommitment } : {}),
    },
    observation: {
      event: obs.event,
      ...(obs.objectId ? { object_id: obs.objectId } : {}),
      state: obs.state,
      at: obs.at,
      ...(obs.fields ? { fields: obs.fields } : {}),
    },
    evidence: { kind: obs.evidenceKind, digest: obs.evidenceDigest },
    level: obs.level,
    witness,
  };
}

async function json(fetchFn: FetchFn, url: string, headers: Record<string, string>): Promise<Record<string, unknown>> {
  const res = await fetchFn(url, { headers: { accept: 'application/json', ...headers } });
  if (!res.ok) throw new Error(`connector GET ${url} -> ${res.status}`);
  return (await res.json()) as Record<string, unknown>;
}

const evidence = (v: unknown): Digest => digestOf(cborEncode(v as never));

// --- GitHub / GitLab --------------------------------------------------------

/** GitHub's web-flow commit-signing (sub)key fingerprints, from https://github.com/web-flow.gpg. */
export const GITHUB_WEBFLOW_FINGERPRINTS = new Set([
  '968479a1aff927e37d1a566bb5690eeebb952194',
]);

export class GitHubConnector {
  constructor(
    private readonly fetchFn: FetchFn,
    private readonly token: string,
    /** Pinned web-flow keys; when omitted, merges can only ever reach W1. */
    private readonly webFlowKeys: PgpPublicKey[] = [],
  ) {}

  /**
   * W2 for a merged PR requires the merge commit to carry GitHub's own
   * web-flow OpenPGP signature and for that signature to verify against
   * the pinned platform key — evidence the relying party can re-check
   * without trusting us or the API response body.
   */
  async prState(owner: string, repo: string, number: number): Promise<Observation> {
    const headers = { authorization: `Bearer ${this.token}` };
    const pr = await json(this.fetchFn, `https://api.github.com/repos/${owner}/${repo}/pulls/${number}`, headers);
    const merged = Boolean(pr['merged_at']);
    let ci = 'unknown';
    let webflow: PgpVerifyResult | null = null;
    const sha = (pr['merge_commit_sha'] as string) || ((pr['head'] as { sha?: string })?.sha ?? '');
    if (sha) {
      const checks = await json(this.fetchFn, `https://api.github.com/repos/${owner}/${repo}/commits/${sha}/check-runs`, headers);
      const runs = (checks['check_runs'] as Array<{ conclusion?: string | null }>) ?? [];
      ci = runs.length > 0 && runs.every((r) => r.conclusion === 'success') ? 'success' : runs.some((r) => r.conclusion === 'failure') ? 'failure' : 'pending';
    }
    if (merged && sha && this.webFlowKeys.length > 0) {
      const commit = await json(this.fetchFn, `https://api.github.com/repos/${owner}/${repo}/commits/${sha}`, headers);
      const verification = (commit['commit'] as { verification?: { signature?: string; payload?: string } } | undefined)?.verification;
      if (verification?.signature && verification.payload) {
        for (const fpr of GITHUB_WEBFLOW_FINGERPRINTS) {
          const r = verifyPgpSignature(Buffer.from(verification.payload), verification.signature, this.webFlowKeys, fpr);
          if (r.valid) {
            webflow = r;
            break;
          }
          webflow = r;
        }
      }
    }
    const w2 = Boolean(webflow?.valid);
    return {
      system: 'pr',
      event: merged ? 'merged' : String(pr['state']),
      objectId: `${owner}/${repo}#${number}`,
      state: merged ? 'merged' : String(pr['state']),
      at: String(pr['merged_at'] ?? pr['updated_at'] ?? new Date().toISOString()),
      fields: { ci, webflow_key: webflow?.fingerprint ?? 'none' },
      evidenceKind: w2 ? 'github-webflow-openpgp' : 'github-api-reread',
      evidenceDigest: evidence({ sha, ci, merged_at: pr['merged_at'], webflow_fingerprint: webflow?.fingerprint ?? null }),
      level: w2 ? 'W2' : 'W1',
    };
  }
}

export function verifyGitHubWebhook(secret: string, rawBody: Buffer, signature256Header: string): boolean {
  const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(signature256Header);
  return a.length === b.length && timingSafeEqual(a, b);
}

export class GitLabConnector {
  constructor(private readonly fetchFn: FetchFn, private readonly token: string, private readonly base = 'https://gitlab.com/api/v4') {}
  async mergeRequestState(projectId: string, iid: number): Promise<Observation> {
    const mr = await json(this.fetchFn, `${this.base}/projects/${encodeURIComponent(projectId)}/merge_requests/${iid}`, {
      'PRIVATE-TOKEN': this.token,
    });
    const pipeline = (mr['head_pipeline'] as { status?: string } | null)?.status ?? 'unknown';
    return {
      system: 'pr',
      event: String(mr['state']),
      objectId: `${projectId}!${iid}`,
      state: mr['state'] === 'merged' ? 'merged' : String(mr['state']),
      at: String(mr['merged_at'] ?? mr['updated_at'] ?? new Date().toISOString()),
      fields: { ci: pipeline === 'success' ? 'success' : pipeline },
      evidenceKind: 'gitlab-api-reread',
      evidenceDigest: evidence(mr['sha']),
      level: 'W1',
    };
  }
}

// --- Payments ---------------------------------------------------------------

export function verifyStripeWebhook(secret: string, rawBody: Buffer, signatureHeader: string, toleranceSeconds = 300, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  const parts = Object.fromEntries(signatureHeader.split(',').map((p) => { const i = p.indexOf('='); return [p.slice(0, i), p.slice(i + 1)]; }));
  if (!parts['t'] || !parts['v1']) return false;
  if (Math.abs(nowSeconds - Number(parts['t'])) > toleranceSeconds) return false;
  const expected = createHmac('sha256', secret).update(`${parts['t']}.`).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(parts['v1']);
  return a.length === b.length && timingSafeEqual(a, b);
}

export class StripeConnector {
  constructor(private readonly fetchFn: FetchFn, private readonly apiKey: string) {}
  private headers = () => ({ authorization: `Bearer ${this.apiKey}` });
  async paymentIntent(id: string): Promise<Observation> {
    const pi = await json(this.fetchFn, `https://api.stripe.com/v1/payment_intents/${id}`, this.headers());
    return {
      system: 'payment',
      event: 'payment_intent',
      objectId: id,
      state: String(pi['status']) === 'succeeded' ? 'succeeded' : String(pi['status']),
      at: new Date(Number(pi['created']) * 1000).toISOString(),
      fields: { amount: Number(pi['amount'] ?? 0) },
      evidenceKind: 'stripe-api-reread',
      evidenceDigest: evidence({ id, status: pi['status'] }),
      level: 'W1',
    };
  }
  async refund(id: string): Promise<Observation> {
    const rf = await json(this.fetchFn, `https://api.stripe.com/v1/refunds/${id}`, this.headers());
    return {
      system: 'refund',
      event: 'refund',
      objectId: id,
      state: String(rf['status']) === 'succeeded' ? 'issued' : String(rf['status']),
      at: new Date(Number(rf['created']) * 1000).toISOString(),
      fields: { amount: Number(rf['amount'] ?? 0) },
      evidenceKind: 'stripe-api-reread',
      evidenceDigest: evidence({ id, status: rf['status'] }),
      level: 'W1',
    };
  }
}

export class AdyenConnector {
  constructor(private readonly hmacKeyHex: string) {}
  /** Adyen notification HMAC: sign the colon-joined field string per Adyen's spec. */
  verifyNotificationHmac(item: Record<string, string>, expectedB64: string): boolean {
    const order = ['pspReference', 'originalReference', 'merchantAccountCode', 'merchantReference', 'amount.value', 'amount.currency', 'eventCode', 'success'];
    const data = order.map((k) => (item[k] ?? '').replace(/\\/g, '\\\\').replace(/:/g, '\\:')).join(':');
    const mac = createHmac('sha256', Buffer.from(this.hmacKeyHex, 'hex')).update(data, 'utf8').digest();
    const a = mac;
    const b = Buffer.from(expectedB64, 'base64');
    return a.length === b.length && timingSafeEqual(a, b);
  }
  observationFromNotification(item: Record<string, string>): Observation {
    return {
      system: 'payment',
      event: item['eventCode'] ?? 'notification',
      objectId: item['pspReference'],
      state: item['success'] === 'true' && item['eventCode'] === 'AUTHORISATION' ? 'succeeded' : (item['eventCode'] ?? 'unknown'),
      at: item['eventDate'] ?? new Date().toISOString(),
      fields: { amount: Number(item['amount.value'] ?? 0) },
      evidenceKind: 'adyen-webhook-hmac',
      evidenceDigest: evidence(item),
      level: 'W1',
    };
  }
}

// --- Help desks --------------------------------------------------------------

export class HelpdeskConnector {
  constructor(
    private readonly fetchFn: FetchFn,
    private readonly vendor: 'zendesk' | 'intercom' | 'freshdesk' | 'hubspot',
    private readonly baseUrl: string,
    private readonly authHeader: Record<string, string>,
  ) {}
  async ticketState(id: string): Promise<Observation> {
    let url: string;
    let state: string;
    let at: string;
    let body: Record<string, unknown>;
    if (this.vendor === 'zendesk') {
      body = await json(this.fetchFn, (url = `${this.baseUrl}/api/v2/tickets/${id}.json`), this.authHeader);
      const t = body['ticket'] as Record<string, unknown>;
      state = String(t['status']);
      at = String(t['updated_at']);
    } else if (this.vendor === 'freshdesk') {
      body = await json(this.fetchFn, (url = `${this.baseUrl}/api/v2/tickets/${id}`), this.authHeader);
      state = Number(body['status']) >= 4 ? 'solved' : 'open';
      at = String(body['updated_at']);
    } else if (this.vendor === 'intercom') {
      body = await json(this.fetchFn, (url = `${this.baseUrl}/conversations/${id}`), this.authHeader);
      state = body['open'] === false ? 'solved' : 'open';
      at = new Date(Number(body['updated_at']) * 1000).toISOString();
    } else {
      body = await json(this.fetchFn, (url = `${this.baseUrl}/crm/v3/objects/tickets/${id}?properties=hs_pipeline_stage,hs_lastmodifieddate`), this.authHeader);
      const props = body['properties'] as Record<string, unknown>;
      state = String(props['hs_pipeline_stage']).toLowerCase().includes('closed') ? 'solved' : String(props['hs_pipeline_stage']);
      at = String(props['hs_lastmodifieddate']);
    }
    return {
      system: 'ticket',
      event: 'ticket-state',
      objectId: id,
      state: state === 'solved' || state === 'closed' ? 'solved' : state,
      at,
      evidenceKind: `${this.vendor}-api-reread`,
      evidenceDigest: evidence({ url, state, at }),
      level: 'W1',
    };
  }
}

// --- Calendars ----------------------------------------------------------------

export class CalendarConnector {
  constructor(private readonly fetchFn: FetchFn, private readonly accessToken: string) {}
  async googleEvent(calendarId: string, eventId: string): Promise<Observation> {
    const ev = await json(this.fetchFn, `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events/${eventId}`, {
      authorization: `Bearer ${this.accessToken}`,
    });
    const attendees = (ev['attendees'] as Array<{ responseStatus?: string }>) ?? [];
    const present = attendees.filter((a) => a.responseStatus === 'accepted').length;
    const start = ((ev['start'] as { dateTime?: string })?.dateTime ?? '') as string;
    const held = ev['status'] === 'confirmed' && new Date(start).getTime() <= Date.now();
    return {
      system: 'meeting',
      event: 'calendar-event',
      objectId: eventId,
      state: held ? 'held' : String(ev['status']),
      at: start || new Date().toISOString(),
      fields: { attendees_present: present, attendees_expected: attendees.length },
      evidenceKind: 'google-calendar-api',
      evidenceDigest: evidence({ eventId, start, present }),
      level: 'W1',
    };
  }
  async microsoftEvent(eventId: string): Promise<Observation> {
    const ev = await json(this.fetchFn, `https://graph.microsoft.com/v1.0/me/events/${eventId}`, {
      authorization: `Bearer ${this.accessToken}`,
    });
    const attendees = (ev['attendees'] as Array<{ status?: { response?: string } }>) ?? [];
    const present = attendees.filter((a) => a.status?.response === 'accepted').length;
    const start = ((ev['start'] as { dateTime?: string })?.dateTime ?? '') as string;
    return {
      system: 'meeting',
      event: 'calendar-event',
      objectId: eventId,
      state: new Date(start).getTime() <= Date.now() ? 'held' : 'scheduled',
      at: start || new Date().toISOString(),
      fields: { attendees_present: present, attendees_expected: attendees.length },
      evidenceKind: 'microsoft-graph-api',
      evidenceDigest: evidence({ eventId, start, present }),
      level: 'W1',
    };
  }
}

// --- Email via DKIM + ARC (W2) ----------------------------------------------------
//
// Full RFC 6376 verification: simple and relaxed canonicalization for both
// header and body, bottom-up consumption of repeated signed headers, l=
// body-length, rsa-sha256 and ed25519-sha256, DMARC alignment of the
// RFC5322.From domain against d=, and DNS evidence captured at verify time
// so the check stays replayable after the signing key rotates (the caller
// stores dnsEvidence with the confirmation; `pinnedKeyTxt` replays offline).
// ARC (RFC 8617): each instance's ARC-Message-Signature and ARC-Seal are
// verified with the same machinery, chain validation (cv=) must be
// none->pass->pass..., and the seal of instance i covers the previous sets.

export interface RawHeader {
  name: string; // as presented
  valueRaw: string; // after the colon, folding kept, CRLF stripped
}

export interface DnsKeyEvidence {
  name: string;
  records: string[];
  publicKeyDigest: Digest;
  fetchedAt: string;
}

export interface DkimResult {
  valid: boolean;
  domain: string;
  selector: string;
  dmarcAligned: boolean | null;
  dnsEvidence: DnsKeyEvidence | null;
  detail: string;
}

function splitMessage(rawMessage: string): { headers: RawHeader[]; body: Buffer } {
  const norm = rawMessage.replace(/\r\n/g, '\n');
  const idx = norm.indexOf('\n\n');
  const headerBlock = idx >= 0 ? norm.slice(0, idx) : norm;
  const bodyText = idx >= 0 ? norm.slice(idx + 2) : '';
  const headers: RawHeader[] = [];
  for (const line of headerBlock.split('\n')) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1]!.valueRaw += `\r\n${line}`;
    } else {
      const i = line.indexOf(':');
      if (i > 0) headers.push({ name: line.slice(0, i), valueRaw: line.slice(i + 1) });
    }
  }
  return { headers, body: Buffer.from(bodyText.replace(/\n/g, '\r\n')) };
}

function unfold(v: string): string {
  return v.replace(/\r\n[ \t]+/g, ' ').replace(/[ \t]+/g, ' ').trim();
}

function canonHeader(h: RawHeader, mode: 'simple' | 'relaxed', isSignatureHeader = false, emptySigValue?: string): string {
  let value = h.valueRaw;
  if (isSignatureHeader && emptySigValue !== undefined) value = emptySigValue;
  if (mode === 'simple') return `${h.name}:${value}\r\n`;
  return `${h.name.toLowerCase()}:${unfold(value)}\r\n`;
}

function canonBodyBytes(body: Buffer, mode: 'simple' | 'relaxed'): Buffer {
  let b = body.toString('binary').replace(/\r\n/g, '\n');
  if (mode === 'relaxed') {
    b = b.split('\n').map((l) => l.replace(/[ \t]+/g, ' ').replace(/[ \t]+$/, '')).join('\n');
    b = b.replace(/\n+$/, '');
    return Buffer.from(b.length ? b.replace(/\n/g, '\r\n') + '\r\n' : '', 'binary');
  }
  b = b.replace(/\n+$/, '\n');
  if (b === '\n') b = '';
  return Buffer.from(b.replace(/\n/g, '\r\n'), 'binary');
}

function parseTags(value: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of value.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    out.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return out;
}

async function verifyDkimLike(opts: {
  headers: RawHeader[];
  body: Buffer;
  sigHeaderName: string; // 'dkim-signature' | 'arc-message-signature'
  resolveTxt: (name: string) => Promise<string[]>;
  pinnedKeyTxt?: string;
  instance?: number; // ARC instance to select among repeated headers
  extraSignedData?: string; // ARC: prior ARC sets are signed as ordinary headers
}): Promise<DkimResult> {
  const fail = (detail: string, domain = ''): DkimResult => ({ valid: false, domain, selector: '', dmarcAligned: null, dnsEvidence: null, detail });
  const candidates = opts.headers.filter((h) => h.name.toLowerCase() === opts.sigHeaderName);
  // ARC instances stack newest-first in the header block; instance i counts from the bottom.
  const sigHeader =
    opts.instance !== undefined
      ? candidates.find((h) => Number(parseTags(unfold(h.valueRaw)).get('i')) === opts.instance)
      : candidates[candidates.length - 1];
  if (!sigHeader) return fail(`no ${opts.sigHeaderName} header`);
  const tags = parseTags(unfold(sigHeader.valueRaw));
  const domain = tags.get('d') ?? '';
  const selector = tags.get('s') ?? '';
  const alg = tags.get('a') ?? 'rsa-sha256';
  if (!['rsa-sha256', 'ed25519-sha256'].includes(alg)) return fail(`unsupported DKIM algorithm ${alg}`, domain);
  const [hModeRaw, bModeRaw] = (tags.get('c') ?? 'simple/simple').split('/');
  const hMode = hModeRaw === 'relaxed' ? 'relaxed' : 'simple';
  const bMode = bModeRaw === 'relaxed' ? 'relaxed' : 'simple';
  const signedNames = (tags.get('h') ?? '').split(':').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!signedNames.includes('from')) return fail('From is not among the signed headers (RFC 6376 requires it)', domain);
  if (opts.sigHeaderName === 'arc-message-signature' && signedNames.includes('arc-seal')) {
    return fail('ARC-Message-Signature MUST NOT sign ARC-Seal (RFC 8617)', domain);
  }
  const bh = (tags.get('bh') ?? '').replace(/\s/g, '');
  const lenTag = tags.get('l') ? Number(tags.get('l')) : null;
  let bodyCanon = canonBodyBytes(opts.body, bMode);
  if (lenTag !== null && Number.isFinite(lenTag)) bodyCanon = bodyCanon.subarray(0, lenTag);
  if (createHash('sha256').update(bodyCanon).digest('base64') !== bh) return fail('body hash mismatch', domain);

  const dnsName = `${selector}._domainkey.${domain}`;
  let records: string[];
  let dnsEvidence: DnsKeyEvidence | null = null;
  if (opts.pinnedKeyTxt) {
    records = [opts.pinnedKeyTxt];
  } else {
    records = (await opts.resolveTxt(dnsName)).map((r) => (Array.isArray(r) ? r.join('') : String(r)));
  }
  const keyRecord = records.map((r) => parseTags(r)).find((t) => t.has('p'));
  const pTag = keyRecord?.get('p')?.replace(/\s/g, '');
  if (!pTag) return fail('no DKIM public key in DNS', domain);
  dnsEvidence = {
    name: dnsName,
    records,
    publicKeyDigest: digestOf(Buffer.from(pTag, 'base64')),
    fetchedAt: new Date().toISOString(),
  };

  // Build the signed header block bottom-up per RFC 6376 section 5.4.
  // Per RFC 6376 §5.4.2, signers may oversign a header (e.g. listing `from`
  // twice in h=) to prevent prepending another instance; nonexistent extra
  // instances evaluate to the null string, provided `from` is present at least once.
  const remaining = new Map<string, RawHeader[]>();
  for (const h of opts.headers) {
    const k = h.name.toLowerCase();
    if (!remaining.has(k)) remaining.set(k, []);
    remaining.get(k)!.push(h);
  }
  if ((remaining.get('from')?.length ?? 0) === 0) {
    return { ...fail('From header missing from message', domain), dnsEvidence };
  }
  let signed = '';
  for (const name of signedNames) {
    const stack = remaining.get(name);
    const h = stack?.pop();
    if (h) signed += canonHeader(h, hMode);
  }
  // the signature header itself, with the b= value emptied (and, for AMS,
  // any extra material the caller folds in first)
  const selfValue = sigHeader.valueRaw.replace(/b\s*=[^;]*/, 'b=');
  const selfCanon = canonHeader({ name: sigHeader.name, valueRaw: selfValue }, hMode, true);
  signed += (opts.extraSignedData ?? '') + selfCanon.replace(/\r\n$/, '');

  const sig = Buffer.from((tags.get('b') ?? '').replace(/\s/g, ''), 'base64');
  try {
    if (alg === 'ed25519-sha256') {
      if (createHash('sha256').update(signed).digest().length !== 32) throw new Error('hash failed');
      const key = createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pTag, 'base64').toString('base64url') } });
      // ed25519-sha256 in DKIM signs the SHA-256 of the canonicalized data
      const digest = createHash('sha256').update(signed).digest();
      const ok = cryptoVerify(null, digest, key, sig);
      return { valid: ok, domain, selector, dmarcAligned: dmarcAlignment(opts.headers, domain), dnsEvidence, detail: ok ? 'DKIM ed25519-sha256 verified' : 'DKIM signature failed' };
    }
    const key = createPublicKey({ key: Buffer.from(pTag, 'base64'), format: 'der', type: 'spki' });
    const v = createVerify('RSA-SHA256');
    v.update(Buffer.from(signed));
    v.end();
    const ok = v.verify(key, sig);
    return { valid: ok, domain, selector, dmarcAligned: dmarcAlignment(opts.headers, domain), dnsEvidence, detail: ok ? 'DKIM rsa-sha256 verified' : 'DKIM signature failed' };
  } catch (e) {
    return { ...fail((e as Error).message, domain), dnsEvidence };
  }
}

function orgDomain(domain: string): string {
  const parts = domain.toLowerCase().split('.');
  return parts.slice(-2).join('.');
}

function dmarcAlignment(headers: RawHeader[], dkimDomain: string): boolean | null {
  const from = headers.find((h) => h.name.toLowerCase() === 'from');
  if (!from) return null;
  const m = /@([A-Za-z0-9.-]+)/.exec(unfold(from.valueRaw));
  if (!m) return null;
  const fromDomain = m[1]!.toLowerCase().replace(/[>\s]+$/, '');
  return orgDomain(fromDomain) === orgDomain(dkimDomain.toLowerCase());
}

export async function verifyDkim(
  rawMessage: string,
  resolveTxt: (name: string) => Promise<string[]>,
  opts: { pinnedKeyTxt?: string } = {},
): Promise<DkimResult> {
  const { headers, body } = splitMessage(rawMessage);
  return verifyDkimLike({
    headers, body, sigHeaderName: 'dkim-signature', resolveTxt,
    ...(opts.pinnedKeyTxt ? { pinnedKeyTxt: opts.pinnedKeyTxt } : {}),
  });
}

export interface ArcResult {
  valid: boolean;
  instances: number;
  sealsVerified: number;
  detail: string;
}

async function verifyArcSealSignature(opts: {
  sealHeader: RawHeader;
  signedData: string;
  resolveTxt: (name: string) => Promise<string[]>;
}): Promise<{ valid: boolean; detail: string }> {
  const tags = parseTags(unfold(opts.sealHeader.valueRaw));
  if (tags.has('h')) return { valid: false, detail: 'h= tag is not permitted in ARC-Seal (RFC 8617 §4.1.3)' };
  const domain = tags.get('d') ?? '';
  const selector = tags.get('s') ?? '';
  const alg = tags.get('a') ?? 'rsa-sha256';
  if (!domain || !selector) return { valid: false, detail: 'ARC-Seal missing d= or s= tag' };
  if (!['rsa-sha256', 'ed25519-sha256'].includes(alg)) {
    return { valid: false, detail: `unsupported ARC-Seal algorithm ${alg}` };
  }
  const dnsName = `${selector}._domainkey.${domain}`;
  let records: string[];
  try {
    records = (await opts.resolveTxt(dnsName)).map((r) => (Array.isArray(r) ? r.join('') : String(r)));
  } catch (e) {
    return { valid: false, detail: `DNS lookup failed for ${dnsName}: ${(e as Error).message}` };
  }
  const keyRecord = records.map((r) => parseTags(r)).find((t) => t.has('p'));
  const pTag = keyRecord?.get('p')?.replace(/\s/g, '');
  if (!pTag) return { valid: false, detail: `no DKIM/ARC public key in DNS for ${dnsName}` };

  const sig = Buffer.from((tags.get('b') ?? '').replace(/\s/g, ''), 'base64');
  try {
    if (alg === 'ed25519-sha256') {
      const key = createPublicKey({
        format: 'jwk',
        key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pTag, 'base64').toString('base64url') },
      });
      const digest = createHash('sha256').update(opts.signedData).digest();
      const ok = cryptoVerify(null, digest, key, sig);
      return { valid: ok, detail: ok ? 'ARC-Seal ed25519-sha256 verified' : 'ARC-Seal ed25519-sha256 signature failed' };
    }
    const key = createPublicKey({ key: Buffer.from(pTag, 'base64'), format: 'der', type: 'spki' });
    const v = createVerify('RSA-SHA256');
    v.update(Buffer.from(opts.signedData));
    v.end();
    const ok = v.verify(key, sig);
    return { valid: ok, detail: ok ? 'ARC-Seal rsa-sha256 verified' : 'ARC-Seal rsa-sha256 signature failed' };
  } catch (e) {
    return { valid: false, detail: (e as Error).message };
  }
}

/**
 * Verify an ARC chain (RFC 8617 §5.2): for each instance k = 1..N (bottom-up),
 * the ARC-Message-Signature must verify like DKIM, the ARC-Seal must verify
 * cryptographically (with relaxed header canonicalization) over all ARC header
 * sets from i = 1 up to i = k in exact order (ARC-Authentication-Results[i],
 * ARC-Message-Signature[i], ARC-Seal[i]), and cv= must read none,pass,pass,...
 */
export async function verifyArcChain(
  rawMessage: string,
  resolveTxt: (name: string) => Promise<string[]>,
): Promise<ArcResult> {
  const { headers, body } = splitMessage(rawMessage);
  const seals = headers.filter((h) => h.name.toLowerCase() === 'arc-seal');
  if (seals.length === 0) return { valid: false, instances: 0, sealsVerified: 0, detail: 'no ARC-Seal present' };
  const arcTagsOf = (h: RawHeader) => parseTags(unfold(h.valueRaw));

  const aarByInst = new Map<number, RawHeader>();
  const amsByInst = new Map<number, RawHeader>();
  const asByInst = new Map<number, RawHeader>();

  for (const h of headers) {
    const lower = h.name.toLowerCase();
    if (lower !== 'arc-authentication-results' && lower !== 'arc-message-signature' && lower !== 'arc-seal') continue;
    const i = Number(arcTagsOf(h).get('i') ?? 0);
    if (!Number.isInteger(i) || i <= 0) {
      return { valid: false, instances: seals.length, sealsVerified: 0, detail: `invalid i= tag in ${h.name}` };
    }
    const target =
      lower === 'arc-authentication-results' ? aarByInst : lower === 'arc-message-signature' ? amsByInst : asByInst;
    if (target.has(i)) {
      return { valid: false, instances: seals.length, sealsVerified: 0, detail: `duplicate ${h.name} for instance i=${i}` };
    }
    target.set(i, h);
  }

  const instances = seals
    .map((h) => ({ h, i: Number(arcTagsOf(h).get('i') ?? 0), cv: arcTagsOf(h).get('cv') ?? '' }))
    .sort((a, b) => a.i - b.i);

  let sealsVerified = 0;
  for (const [idx, inst] of instances.entries()) {
    const k = idx + 1;
    if (inst.i !== k) {
      return { valid: false, instances: instances.length, sealsVerified, detail: `ARC instance numbering broken at ${inst.i}` };
    }
    if (!aarByInst.has(k) || !amsByInst.has(k) || !asByInst.has(k)) {
      return { valid: false, instances: instances.length, sealsVerified, detail: `incomplete ARC header set at i=${k}` };
    }
    const expectedCv = k === 1 ? 'none' : 'pass';
    if (inst.cv !== expectedCv) {
      return { valid: false, instances: instances.length, sealsVerified, detail: `ARC cv=${inst.cv} at i=${k}, expected ${expectedCv}` };
    }
    const ams = await verifyDkimLike({ headers, body, sigHeaderName: 'arc-message-signature', resolveTxt, instance: k });
    if (!ams.valid) {
      return { valid: false, instances: instances.length, sealsVerified, detail: `AMS i=${k}: ${ams.detail}` };
    }

    // Build RFC 8617 §5.2.1 / §4.1.3 ARC-Seal signed data over i = 1..k (relaxed canonicalization only)
    let sealSignedData = '';
    for (let j = 1; j <= k; j++) {
      sealSignedData += canonHeader(aarByInst.get(j)!, 'relaxed');
      sealSignedData += canonHeader(amsByInst.get(j)!, 'relaxed');
      const sealJ = asByInst.get(j)!;
      if (j < k) {
        sealSignedData += canonHeader(sealJ, 'relaxed');
      } else {
        const selfValue = sealJ.valueRaw.replace(/b\s*=[^;]*/, 'b=');
        const selfCanon = canonHeader({ name: sealJ.name, valueRaw: selfValue }, 'relaxed', true);
        sealSignedData += selfCanon.replace(/\r\n$/, '');
      }
    }

    const sealRes = await verifyArcSealSignature({
      sealHeader: inst.h,
      signedData: sealSignedData,
      resolveTxt,
    });
    if (!sealRes.valid) {
      return { valid: false, instances: instances.length, sealsVerified, detail: `ARC-Seal i=${k}: ${sealRes.detail}` };
    }
    sealsVerified++;
  }
  return {
    valid: true,
    instances: instances.length,
    sealsVerified,
    detail: `ARC chain of ${instances.length} instance(s) and ${sealsVerified} seal(s) verified`,
  };
}


// --- E-invoicing networks: network-signed receipts (W2 via XMLDSig) ----------------
//
// "Accepted" in the XML body is never enough for W2: the receipt must carry
// an enveloped XMLDSig signature from a certificate the caller pinned
// (PEPPOL AP / SdI signing certs) AND pass PEPPOL BIS Billing 3.0 Schematron
// or FatturaPA v1.2.2 XSD structural/semantic validation. Unsigned, unpinned,
// or schema-invalid documents degrade to W1 with explicit validation errors.

export function peppolObservation(
  receiptXml: string,
  invoiceId: string,
  opts: { pinnedSignerCertPems?: string[]; accessPointAck?: boolean } = {},
): Observation & { validationErrors?: string[]; detail?: string } {
  const hasAccessPointAck =
    opts.accessPointAck === true ||
    (/<(?:\w+:)?ApplicationResponse[\s>]|<(?:\w+:)?ResponseCode[^>]*>\s*(?:AP|AB)\s*</i.test(
      receiptXml,
    ) &&
      !/Rejected/i.test(receiptXml));
  const rejected = /Rejected/i.test(receiptXml);
  const sig = verifyXmlSignature(receiptXml, opts.pinnedSignerCertPems ?? []);
  const schema = validatePeppolBis3(receiptXml);
  const w2 = hasAccessPointAck && sig.valid && schema.valid;
  const selfValidatedOnly = !hasAccessPointAck && !rejected && schema.valid;
  const state = w2
    ? 'accepted'
    : selfValidatedOnly
      ? 'validated, not confirmed'
      : rejected
        ? 'rejected'
        : !schema.valid
          ? 'invalid-schema'
          : 'validated, not confirmed';
  return {
    system: 'invoice',
    event: 'peppol-delivery',
    objectId: invoiceId,
    state,
    at: new Date().toISOString(),
    fields: {
      signer: sig.signerSubject ?? 'unsigned',
      schema_valid: schema.valid,
      access_point_ack: hasAccessPointAck,
      validation_status: w2 ? 'confirmed' : selfValidatedOnly ? 'validated, not confirmed' : state,
      ...(schema.errors.length > 0 ? { validation_errors: schema.errors.join('; ') } : {}),
    },
    evidenceKind: w2
      ? 'peppol-receipt-xmldsig'
      : !schema.valid
        ? 'peppol-bis3-validation-failed'
        : selfValidatedOnly
          ? 'peppol-bis3-self-validated'
          : 'peppol-receipt-signature-unverified',
    evidenceDigest: digestOf(Buffer.from(receiptXml)),
    level: w2 ? 'W2' : 'W1',
    detail: w2 ? 'confirmed by PEPPOL Access Point receipt' : 'validated, not confirmed',
    ...(schema.errors.length > 0 ? { validationErrors: schema.errors } : {}),
  };
}

export function sdiObservation(
  notificationXml: string,
  invoiceId: string,
  opts: { pinnedSignerCertPems?: string[]; sdiReceiptAck?: boolean } = {},
): Observation & { validationErrors?: string[]; detail?: string } {
  // SdI notifications require an actual SdI receipt (RC RicevutaConsegna / NE NotificaEsito)
  // to reach W2; self-validation of a FatturaPA XML document alone is W1 ('validated, not confirmed').
  const hasSdiReceipt =
    opts.sdiReceiptAck === true ||
    /<(?:\w+:)?(?:RicevutaConsegna|NotificaEsito)[\s>]/i.test(notificationXml);
  const sig = verifyXmlSignature(notificationXml, opts.pinnedSignerCertPems ?? []);
  const schema = validateFatturaPA(notificationXml);
  const w2 = hasSdiReceipt && sig.valid && schema.valid;
  const selfValidatedOnly = !hasSdiReceipt && schema.valid;
  const state = w2
    ? 'accepted'
    : selfValidatedOnly
      ? 'validated, not confirmed'
      : !schema.valid
        ? 'invalid-schema'
        : 'validated, not confirmed';
  return {
    system: 'invoice',
    event: 'sdi-notification',
    objectId: invoiceId,
    state,
    at: new Date().toISOString(),
    fields: {
      signer: sig.signerSubject ?? 'unsigned',
      schema_valid: schema.valid,
      sdi_receipt: hasSdiReceipt,
      validation_status: w2 ? 'confirmed' : selfValidatedOnly ? 'validated, not confirmed' : state,
      ...(schema.errors.length > 0 ? { validation_errors: schema.errors.join('; ') } : {}),
    },
    evidenceKind: w2
      ? 'sdi-notification-xmldsig'
      : !schema.valid
        ? 'fatturapa-validation-failed'
        : selfValidatedOnly
          ? 'fatturapa-self-validated'
          : 'sdi-notification-signature-unverified',
    evidenceDigest: digestOf(Buffer.from(notificationXml)),
    level: w2 ? 'W2' : 'W1',
    detail: w2 ? 'confirmed by signed SdI receipt' : 'validated, not confirmed',
    ...(schema.errors.length > 0 ? { validationErrors: schema.errors } : {}),
  };
}

/**
 * Unified e-invoicing observation router (`einvoiceObservation`):
 * dispatches FatturaPA / SdI XML to `sdiObservation` and PEPPOL UBL XML to `peppolObservation`.
 * Without an external PEPPOL Access Point `<ApplicationResponse>` or SdI `<RicevutaConsegna>`/`<NotificaEsito>`
 * receipt, the returned level is always `'W1'` with `detail: 'validated, not confirmed'` (and the word
 * "confirmation" is never emitted on the W1 path).
 */
export function einvoiceObservation(
  xml: string,
  invoiceId: string,
  opts: { pinnedSignerCertPems?: string[]; accessPointAck?: boolean; sdiReceiptAck?: boolean } = {},
): Observation & { validationErrors?: string[]; detail?: string } {
  if (/<(?:\w+:)?(?:FatturaElettronica|RicevutaConsegna|NotificaEsito)[\s>]/i.test(xml)) {
    return sdiObservation(xml, invoiceId, opts);
  }
  return peppolObservation(xml, invoiceId, opts);
}

// --- Open banking (PSD2 AISP) ---------------------------------------------------

export class OpenBankingConnector {
  constructor(private readonly fetchFn: FetchFn, private readonly aggregatorBase: string, private readonly accessToken: string) {}
  async paymentCredited(accountId: string, expectedAmountMinor: number, reference: string): Promise<Observation> {
    const tx = await json(this.fetchFn, `${this.aggregatorBase}/accounts/${accountId}/transactions?reference=${encodeURIComponent(reference)}`, {
      authorization: `Bearer ${this.accessToken}`,
    });
    const list = (tx['transactions'] as Array<Record<string, unknown>>) ?? [];
    const hit = list.find((t) => Number((t['amount'] as { amount?: string })?.amount ?? 0) * 100 >= expectedAmountMinor);
    return {
      system: 'payment',
      event: 'account-credit',
      objectId: reference,
      state: hit ? 'succeeded' : 'not-found',
      at: (hit?.['bookingDate'] as string) ?? new Date().toISOString(),
      fields: { amount: hit ? expectedAmountMinor : 0 },
      evidenceKind: 'psd2-aisp-read',
      evidenceDigest: evidence({ accountId, reference, found: Boolean(hit) }),
      level: 'W1',
    };
  }
}

// --- AWS CloudTrail digest files (W2) ---------------------------------------------
//
// Integrity exactly per AWS's documented custom validation and the AWS
// CLI validator (awscli/customizations/cloudtrail/validation.py): digest
// files form a hash chain (SHA-256 of each digest file's bytes is recorded
// as previousDigestHashValue in the next) and every digest file is
// RSA-signed by AWS. The signature travels in the S3 object *metadata*
// (`signature` + `signature-algorithm`), not the file body — which is why
// the signed string can cover the file hash:
// `${digestEndTime}\n${bucket}/${digestS3Object}\n${hex(sha256(digestFile))}\n${previousDigestSignatureOrNull}`
// under SHA256withRSA (PKCS#1 v1.5). Log file contents hash to the
// hashValue entries inside covering digests. W2 only when the whole chain
// presented covers the log file containing the call, every link checks
// out, and the AWS public key fingerprint matches a key the caller pinned
// (AWS rotates these quarterly, published via ListPublicKeys/GetPublicKey).

export interface CloudTrailDigestFile {
  /** Exact bytes of the digest file as stored in S3 (decompressed). */
  content: Buffer;
  /** Hex signature from the S3 object metadata (`signature` key). */
  signatureHex: string;
}

interface ParsedDigest {
  digestS3Bucket?: string;
  digestS3Object?: string;
  previousDigestS3Object?: string;
  previousDigestHashValue?: string;
  previousDigestHashAlgorithm?: string;
  previousDigestSignature?: string;
  digestStartTime?: string;
  digestEndTime?: string;
  digestPublicKeyFingerprint?: string;
  logFiles?: Array<{ s3Object?: string; hashValue?: string; hashAlgorithm?: string }>;
}

const sha256Hex = (b: Buffer) => createHash('sha256').update(b).digest('hex');

export interface CloudTrailVerdict {
  chainValid: boolean;
  detail: string;
  /** s3Object names of log files whose contents hashed correctly inside a verified digest. */
  coveredLogFiles: string[];
}

export function verifyCloudTrailChain(input: {
  digestFiles: CloudTrailDigestFile[];
  logFileContents: Map<string, Buffer>;
  /** hex fingerprint -> PEM public key, pinned from AWS GetPublicKey. */
  awsPublicKeys: Map<string, string>;
}): CloudTrailVerdict {
  const fail = (detail: string): CloudTrailVerdict => ({ chainValid: false, detail, coveredLogFiles: [] });
  let digests: Array<{ raw: Buffer; parsed: ParsedDigest }>;
  try {
    digests = input.digestFiles.map((d) => ({ raw: d.content, parsed: JSON.parse(d.content.toString('utf8')) as ParsedDigest }));
  } catch (e) {
    return fail(`digest file is not JSON: ${(e as Error).message}`);
  }
  if (digests.length === 0) return fail('no digest files presented');
  const byObject = new Map(digests.map((d) => [d.parsed.digestS3Object ?? '', d]));
  // Order the chain: start from any digest, follow previousDigestS3Object.
  const ordered: typeof digests = [];
  const seen = new Set<string>();
  let cursor = digests[digests.length - 1]!;
  while (cursor) {
    const name = cursor.parsed.digestS3Object ?? '';
    if (seen.has(name)) return fail('digest chain contains a cycle');
    seen.add(name);
    ordered.unshift(cursor);
    const prevName = cursor.parsed.previousDigestS3Object;
    if (!prevName) break;
    const prev = byObject.get(prevName);
    if (!prev) return fail(`missing previous digest file ${prevName} (chain gap)`);
    cursor = prev;
  }
  if (ordered.length !== digests.length) return fail('presented digest files do not form one chain');

  const covered: string[] = [];
  const signatureOf = (j: number) => input.digestFiles[digests.indexOf(ordered[j]!)]!.signatureHex;
  for (const [i, d] of ordered.entries()) {
    const p = d.parsed;
    if (!p.digestPublicKeyFingerprint || !p.digestEndTime || !p.digestS3Object || !p.digestS3Bucket) {
      return fail(`digest ${p.digestS3Object ?? i} lacks required fields`);
    }
    const keyPem = input.awsPublicKeys.get(p.digestPublicKeyFingerprint.toLowerCase());
    if (!keyPem) return fail(`AWS public key fingerprint ${p.digestPublicKeyFingerprint} is not pinned`);
    const signatureHex = signatureOf(i);
    // AWS CLI: a missing previousDigestSignature is the literal 'null'.
    const prevSig = p.previousDigestSignature ?? 'null';
    const dataToSign = `${p.digestEndTime}\n${p.digestS3Bucket}/${p.digestS3Object}\n${sha256Hex(d.raw)}\n${prevSig}`;
    let sigOk = false;
    try {
      const v = createVerify('RSA-SHA256');
      v.update(dataToSign);
      v.end();
      sigOk = v.verify(keyPem, Buffer.from(signatureHex, 'hex'));
    } catch {
      sigOk = false;
    }
    if (!sigOk) return fail(`AWS digest signature does not verify for ${p.digestS3Object}`);
    if (i > 0) {
      const prev = ordered[i - 1]!;
      if ((p.previousDigestHashValue ?? '').toLowerCase() !== sha256Hex(prev.raw)) {
        return fail(`hash chain broken before ${p.digestS3Object}`);
      }
      if ((p.previousDigestSignature ?? '').toLowerCase() !== signatureOf(i - 1).toLowerCase()) {
        return fail(`previousDigestSignature mismatch at ${p.digestS3Object}`);
      }
    }
    for (const lf of p.logFiles ?? []) {
      if (!lf.s3Object || !lf.hashValue) continue;
      const content = input.logFileContents.get(lf.s3Object);
      if (!content) continue;
      if (sha256Hex(content) === lf.hashValue.toLowerCase()) covered.push(lf.s3Object);
      else return fail(`log file ${lf.s3Object} content hash does not match its digest entry`);
    }
  }
  return { chainValid: true, detail: `CloudTrail digest chain of ${ordered.length} file(s) verified (AWS signatures + hash chain)`, coveredLogFiles: covered };
}

export function cloudTrailObservation(input: {
  digestFiles: CloudTrailDigestFile[];
  logFileContents: Map<string, Buffer>;
  /** The log file (s3Object) that contains the observed call. */
  containingLogFile: string;
  awsPublicKeys: Map<string, string>;
  apiCallObserved: string;
}): Observation & { chainValid: boolean } {
  const verdict = verifyCloudTrailChain(input);
  const covered = verdict.chainValid && verdict.coveredLogFiles.includes(input.containingLogFile);
  return {
    system: 'cloudtrail',
    event: 'api-call',
    objectId: input.apiCallObserved,
    state: covered ? 'recorded' : 'unverified',
    at: new Date().toISOString(),
    fields: { log_file: input.containingLogFile },
    evidenceKind: 'cloudtrail-digest-chain-aws-signature',
    evidenceDigest: evidence({ detail: verdict.detail, covered: verdict.coveredLogFiles }),
    level: covered ? 'W2' : 'W1',
    chainValid: verdict.chainValid,
  };
}

// --- zkTLS web proofs (W3, TLSNotary/tlsn) -----------------------------------
//
// W3 is only ever produced from real TLSNotary presentations verified by the
// hv-webproof binary (services/webproof, on the pinned tlsn crates). A
// presentation proves an HTTPS server sent the revealed bytes in a session
// witnessed by one notary; requiring `quorum` distinct trusted notaries to
// have witnessed sessions revealing the same value from the same host is
// what keeps a single notary (or a prover colluding with one) from minting
// W3 alone. Anything short of that degrades honestly to W1/unconfirmed.

export interface WebProofVerdict {
  verified: boolean;
  trusted_notary: boolean;
  notary_key_alg: string;
  notary_key: string;
  server_name: string | null;
  time_unix: number | null;
  sent: string | null;
  received: string | null;
  received_sha256: string | null;
  error: string | null;
}

/** Runs hv-webproof; injectable for tests. Resolves {code, stdout}. */
export type ExecFn = (argv: string[]) => Promise<{ code: number; stdout: string }>;

export class TlsnWebProofVerifier {
  constructor(
    private readonly bin: string,
    private readonly trustedNotaryKeys: string[],
    private readonly exec: ExecFn = defaultExec(bin),
    private readonly rootCaDerPaths: string[] = [],
  ) {}

  async verifyPresentation(presentationPath: string): Promise<WebProofVerdict> {
    const argv = [
      'verify',
      '--presentation', presentationPath,
      '--trusted-notary-keys', this.trustedNotaryKeys.join(','),
      ...this.rootCaDerPaths.flatMap((p) => ['--root-ca-der', p]),
    ];
    const { stdout } = await this.exec(argv);
    const line = stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop();
    if (!line) throw new Error(`hv-webproof produced no verdict for ${presentationPath}`);
    return JSON.parse(line) as WebProofVerdict;
  }

  /**
   * Build the observation for `expectedSubstring` at `url` from verified
   * presentations. W3 iff at least `quorum` presentations from distinct
   * trusted notaries verify, name the URL's host as the TLS server, and
   * reveal the expected value in the received transcript.
   */
  async webProofObservation(input: {
    url: string;
    expectedSubstring: string;
    presentationPaths: string[];
    quorum?: number;
  }): Promise<Observation> {
    const quorum = input.quorum ?? 2;
    const host = new URL(input.url).hostname;
    const verdicts = await Promise.all(
      input.presentationPaths.map((p) => this.verifyPresentation(p).catch(() => null)),
    );
    const good = verdicts.filter(
      (v): v is WebProofVerdict =>
        v !== null && v.verified && v.trusted_notary && v.server_name === host &&
        (v.received ?? '').includes(input.expectedSubstring),
    );
    const notaries = new Set(good.map((v) => v.notary_key));
    const w3 = notaries.size >= quorum;
    const latest = good.reduce((m, v) => Math.max(m, v.time_unix ?? 0), 0);
    return {
      system: 'web',
      event: 'https-observation',
      objectId: input.url,
      state: w3 ? 'observed' : 'unconfirmed',
      at: latest > 0 ? new Date(latest * 1000).toISOString() : new Date().toISOString(),
      fields: { notaries: notaries.size, quorum, host },
      evidenceKind: 'tlsn-presentation-quorum',
      evidenceDigest: evidence(good.map((v) => [v.notary_key, v.received_sha256])),
      level: w3 ? 'W3' : 'W1',
    };
  }
}

function defaultExec(bin: string): ExecFn {
  return async (argv) => {
    const { execFile } = await import('node:child_process');
    return new Promise((resolve) => {
      execFile(bin, argv, { maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
        const code = err && typeof (err as { code?: unknown }).code === 'number' ? ((err as { code: number }).code) : err ? 1 : 0;
        resolve({ code, stdout: stdout?.toString() ?? '' });
      });
    });
  };
}
