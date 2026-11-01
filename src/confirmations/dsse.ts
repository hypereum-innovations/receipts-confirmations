// SPDX-License-Identifier: Apache-2.0
/**
 * Dead Simple Signing Envelope (DSSE) + in-toto Statement v1 verification.
 *
 * Implements the DSSE v1 Pre-Authentication Encoding (PAE):
 *   "DSSEv1 " + ASCII_LEN(payloadType) + " " + payloadType + " " + ASCII_LEN(payload) + " " + payload
 * where lengths are UTF-8 / raw byte lengths (never character counts),
 * multi-signature creation and threshold verification (Ed25519 and ECDSA P-256,
 * supporting both ASN.1 DER and IEEE P1363 signatures), and strict parsing and
 * structural validation for in-toto Statement v1 attestations
 * (`_type: "https://in-toto.io/Statement/v1"`).
 */
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { cborEncode } from '../core/cbor.js';
import { digestOf } from '../core/capsule.js';
import type { Observation } from './connectors/index.js';

export const INTOTO_STATEMENT_V1_TYPE = 'https://in-toto.io/Statement/v1' as const;
export const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json' as const;

export interface DsseSignature {
  keyid: string;
  sig: string; // base64
}

export interface DsseEnvelope {
  payload: string; // base64
  payloadType: string;
  signatures: DsseSignature[];
}

export interface DsseSigner {
  keyid: string;
  privateKey: KeyObject | string;
}

export interface DsseVerifierKey {
  keyid: string;
  publicKey: KeyObject | string;
}

export interface DsseVerifyResult {
  valid: boolean;
  verifiedKeyIds: string[];
  payloadType: string;
  payload: Buffer;
  thresholdMet: boolean;
  detail: string;
}

export interface InTotoSubject {
  name: string;
  digest: Record<string, string>;
}

export interface InTotoStatementV1 {
  _type: typeof INTOTO_STATEMENT_V1_TYPE;
  subject: InTotoSubject[];
  predicateType: string;
  predicate: Record<string, unknown>;
}

/**
 * DSSE Pre-Authentication Encoding (PAE):
 * `DSSEv1 <byteLen(payloadType)> <payloadType> <byteLen(payload)> <payload>`
 */
export function dssePae(payloadType: string, payload: Buffer): Buffer {
  const typeBytes = Buffer.from(payloadType, 'utf8');
  const prefix = Buffer.from(`DSSEv1 ${typeBytes.byteLength} `, 'ascii');
  const mid = Buffer.from(` ${payload.byteLength} `, 'ascii');
  return Buffer.concat([prefix, typeBytes, mid, payload]);
}

function toPrivateKey(k: KeyObject | string): KeyObject {
  return typeof k === 'string' ? createPrivateKey(k) : k;
}

function toPublicKey(k: KeyObject | string): KeyObject {
  return typeof k === 'string' ? createPublicKey(k) : k;
}

function signPaeWithKey(pae: Buffer, priv: KeyObject): Buffer {
  if (priv.asymmetricKeyType === 'ed25519') {
    return cryptoSign(null, pae, priv);
  }
  if (priv.asymmetricKeyType === 'ec') {
    return cryptoSign('sha256', pae, priv);
  }
  throw new Error(`Unsupported DSSE signing key type: ${String(priv.asymmetricKeyType)}`);
}

function verifyPaeWithKey(pae: Buffer, sig: Buffer, pub: KeyObject): boolean {
  try {
    if (pub.asymmetricKeyType === 'ed25519') {
      return cryptoVerify(null, pae, pub, sig);
    }
    if (pub.asymmetricKeyType === 'ec') {
      if (cryptoVerify('sha256', pae, pub, sig)) return true;
      if (sig.length === 64) {
        return cryptoVerify('sha256', pae, { key: pub, dsaEncoding: 'ieee-p1363' }, sig);
      }
      return false;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Sign a payload into a DSSE envelope with one or more signers (Ed25519 or ECDSA P-256).
 */
export function signDsse(payloadType: string, payload: Buffer, signers: DsseSigner[]): DsseEnvelope {
  if (signers.length === 0) throw new Error('DSSE signing requires at least one signer');
  const pae = dssePae(payloadType, payload);
  const signatures: DsseSignature[] = signers.map((s) => {
    const priv = toPrivateKey(s.privateKey);
    const sig = signPaeWithKey(pae, priv);
    return {
      keyid: s.keyid,
      sig: sig.toString('base64'),
    };
  });
  return {
    payloadType,
    payload: payload.toString('base64'),
    signatures,
  };
}

/**
 * Verify a DSSE envelope against a set of verifier keys and an optional threshold.
 */
export function verifyDsse(
  envelope: DsseEnvelope,
  verifiers: DsseVerifierKey[],
  opts: { threshold?: number; expectedPayloadType?: string } = {},
): DsseVerifyResult {
  const threshold = opts.threshold ?? 1;
  const fail = (detail: string, payload = Buffer.alloc(0), verifiedKeyIds: string[] = []): DsseVerifyResult => ({
    valid: false,
    verifiedKeyIds,
    payloadType: envelope?.payloadType ?? '',
    payload,
    thresholdMet: false,
    detail,
  });

  if (!envelope || typeof envelope.payloadType !== 'string' || typeof envelope.payload !== 'string') {
    return fail('malformed DSSE envelope');
  }
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    return fail('DSSE envelope contains no signatures');
  }
  if (threshold < 1 || verifiers.length === 0) {
    return fail('no DSSE verifier keys configured');
  }
  if (opts.expectedPayloadType && envelope.payloadType !== opts.expectedPayloadType) {
    return fail(`unexpected payloadType "${envelope.payloadType}" (expected "${opts.expectedPayloadType}")`);
  }

  let payload: Buffer;
  try {
    payload = Buffer.from(envelope.payload, 'base64');
  } catch {
    return fail('invalid base64 payload');
  }

  const pae = dssePae(envelope.payloadType, payload);
  const verifierMap = new Map<string, KeyObject>();
  for (const v of verifiers) {
    verifierMap.set(v.keyid, toPublicKey(v.publicKey));
  }

  const verifiedSet = new Set<string>();
  for (const sigEntry of envelope.signatures) {
    if (!sigEntry || typeof sigEntry.sig !== 'string') continue;
    const sigBytes = Buffer.from(sigEntry.sig, 'base64');
    if (sigEntry.keyid && verifierMap.has(sigEntry.keyid)) {
      const pub = verifierMap.get(sigEntry.keyid)!;
      if (verifyPaeWithKey(pae, sigBytes, pub)) {
        verifiedSet.add(sigEntry.keyid);
      }
    } else if (!sigEntry.keyid) {
      for (const [kid, pub] of verifierMap.entries()) {
        if (verifyPaeWithKey(pae, sigBytes, pub)) {
          verifiedSet.add(kid);
          break;
        }
      }
    }
  }

  const verifiedKeyIds = [...verifiedSet];
  const thresholdMet = verifiedKeyIds.length >= threshold;
  return {
    valid: thresholdMet,
    verifiedKeyIds,
    payloadType: envelope.payloadType,
    payload,
    thresholdMet,
    detail: thresholdMet
      ? `DSSE verified (${verifiedKeyIds.length}/${threshold} threshold met by [${verifiedKeyIds.join(', ')}])`
      : `DSSE threshold not met (${verifiedKeyIds.length}/${threshold} verified)`,
  };
}

const HEX_DIGEST_LENGTHS: Record<string, number> = {
  sha256: 64,
  sha384: 96,
  sha512: 128,
  sha1: 40,
};

/**
 * Parse and validate an in-toto Statement v1 JSON object or Buffer/string.
 */
export function validateInTotoStatementV1(input: unknown): {
  valid: boolean;
  statement: InTotoStatementV1 | null;
  errors: string[];
} {
  let obj: unknown = input;
  if (Buffer.isBuffer(input) || typeof input === 'string') {
    try {
      obj = JSON.parse(Buffer.isBuffer(input) ? input.toString('utf8') : input);
    } catch (e) {
      return { valid: false, statement: null, errors: [`invalid JSON: ${(e as Error).message}`] };
    }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return { valid: false, statement: null, errors: ['in-toto statement must be a JSON object'] };
  }
  const rec = obj as Record<string, unknown>;
  const errors: string[] = [];

  if (rec['_type'] !== INTOTO_STATEMENT_V1_TYPE) {
    errors.push(`invalid _type "${String(rec['_type'])}" (expected "${INTOTO_STATEMENT_V1_TYPE}")`);
  }

  if (!Array.isArray(rec['subject']) || rec['subject'].length === 0) {
    errors.push('subject must be a non-empty array of Subject objects');
  } else {
    for (const [idx, sub] of rec['subject'].entries()) {
      if (!sub || typeof sub !== 'object' || Array.isArray(sub)) {
        errors.push(`subject[${idx}] must be an object`);
        continue;
      }
      const s = sub as Record<string, unknown>;
      if (typeof s['name'] !== 'string' || s['name'].trim().length === 0) {
        errors.push(`subject[${idx}].name must be a non-empty string`);
      }
      const dig = s['digest'];
      if (!dig || typeof dig !== 'object' || Array.isArray(dig)) {
        errors.push(`subject[${idx}].digest must be a non-empty DigestSet object`);
      } else {
        const entries = Object.entries(dig as Record<string, unknown>);
        if (entries.length === 0) {
          errors.push(`subject[${idx}].digest must contain at least one algorithm`);
        }
        for (const [alg, val] of entries) {
          if (typeof val !== 'string' || !/^[0-9a-f]+$/i.test(val)) {
            errors.push(`subject[${idx}].digest.${alg} must be a lowercase hex string`);
          } else if (HEX_DIGEST_LENGTHS[alg] && val.length !== HEX_DIGEST_LENGTHS[alg]) {
            errors.push(`subject[${idx}].digest.${alg} must have length ${HEX_DIGEST_LENGTHS[alg]}`);
          }
        }
      }
    }
  }

  if (typeof rec['predicateType'] !== 'string' || !/^https?:\/\/|^urn:/.test(rec['predicateType'])) {
    errors.push(`predicateType must be a valid URI (got "${String(rec['predicateType'])}")`);
  }

  if (!rec['predicate'] || typeof rec['predicate'] !== 'object' || Array.isArray(rec['predicate'])) {
    errors.push('predicate must be a JSON object');
  }

  return {
    valid: errors.length === 0,
    statement: errors.length === 0 ? (rec as unknown as InTotoStatementV1) : null,
    errors,
  };
}

/**
 * Verify a DSSE envelope carrying an in-toto Statement v1 payload.
 */
export function verifyInTotoDsse(
  envelope: DsseEnvelope,
  verifiers: DsseVerifierKey[],
  opts: {
    threshold?: number;
    expectedPredicateType?: string;
    expectedSubjectDigest?: { name?: string; alg: string; hex: string };
  } = {},
): {
  valid: boolean;
  statement: InTotoStatementV1 | null;
  verifiedKeyIds: string[];
  errors: string[];
  detail: string;
} {
  const dsseRes = verifyDsse(envelope, verifiers, {
    ...(opts.threshold !== undefined ? { threshold: opts.threshold } : {}),
    expectedPayloadType: INTOTO_PAYLOAD_TYPE,
  });
  if (!dsseRes.valid) {
    return {
      valid: false,
      statement: null,
      verifiedKeyIds: dsseRes.verifiedKeyIds,
      errors: [dsseRes.detail],
      detail: dsseRes.detail,
    };
  }

  const stmtRes = validateInTotoStatementV1(dsseRes.payload);
  if (!stmtRes.valid || !stmtRes.statement) {
    return {
      valid: false,
      statement: null,
      verifiedKeyIds: dsseRes.verifiedKeyIds,
      errors: stmtRes.errors,
      detail: `in-toto Statement v1 invalid: ${stmtRes.errors.join('; ')}`,
    };
  }

  const stmt = stmtRes.statement;
  const errors: string[] = [];
  if (opts.expectedPredicateType && stmt.predicateType !== opts.expectedPredicateType) {
    errors.push(`predicateType "${stmt.predicateType}" does not match expected "${opts.expectedPredicateType}"`);
  }
  if (opts.expectedSubjectDigest) {
    const { name, alg, hex } = opts.expectedSubjectDigest;
    const matched = stmt.subject.some(
      (s) => (!name || s.name === name) && s.digest[alg]?.toLowerCase() === hex.toLowerCase(),
    );
    if (!matched) {
      errors.push(`no subject matched expected digest ${alg}:${hex}`);
    }
  }

  const ok = errors.length === 0;
  return {
    valid: ok,
    statement: ok ? stmt : null,
    verifiedKeyIds: dsseRes.verifiedKeyIds,
    errors,
    detail: ok
      ? `in-toto Statement v1 DSSE verified (${stmt.predicateType}, signers: ${dsseRes.verifiedKeyIds.join(', ')})`
      : errors.join('; '),
  };
}

/**
 * Convert a DSSE + in-toto Statement v1 verification into a Confirmation Observation.
 */
export function dsseObservation(
  envelope: DsseEnvelope,
  verifiers: DsseVerifierKey[],
  opts: {
    threshold?: number;
    expectedPredicateType?: string;
    expectedSubjectDigest?: { name?: string; alg: string; hex: string };
  } = {},
): Observation {
  const res = verifyInTotoDsse(envelope, verifiers, opts);
  const firstSubject = res.statement?.subject[0]?.name ?? 'unknown';
  return {
    system: 'attestation',
    event: 'in-toto-dsse',
    objectId: firstSubject,
    state: res.valid ? 'attested' : 'unverified',
    at: new Date().toISOString(),
    fields: {
      predicate_type: res.statement?.predicateType ?? 'invalid',
      verified_signers: res.verifiedKeyIds.length,
    },
    evidenceKind: res.valid ? 'in-toto-dsse-v1' : 'in-toto-dsse-unverified',
    evidenceDigest: digestOf(cborEncode(envelope as never)),
    level: res.valid ? 'W2' : 'W1',
  };
}
