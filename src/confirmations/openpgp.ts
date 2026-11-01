// SPDX-License-Identifier: Apache-2.0
/**
 * Minimal OpenPGP (RFC 4880/9580) signature verification for platform
 * signatures we must check on the W2 path — GitHub's web-flow commit
 * signing in particular. Scope is deliberately narrow and fail-closed:
 * v4 keys and signatures, RSA and Ed25519, SHA-256/SHA-512 hashes, binary
 * document signatures (0x00) as git uses for commit signing. No encryption,
 * no trust DB: the caller pins the platform key (e.g. the armored key from
 * https://github.com/web-flow.gpg) and its fingerprint.
 */
import { createHash, createPublicKey, createVerify, verify as cryptoVerify } from 'node:crypto';

export interface PgpPacket {
  tag: number;
  body: Buffer;
}

export function parsePackets(buf: Buffer): PgpPacket[] {
  const out: PgpPacket[] = [];
  let i = 0;
  while (i < buf.length) {
    const first = buf[i++]!;
    if (!(first & 0x80)) throw new Error('bad OpenPGP packet header');
    let tag: number;
    let len: number;
    if (first & 0x40) {
      // new format
      tag = first & 0x3f;
      const b = buf[i++]!;
      if (b < 192) len = b;
      else if (b < 224) len = (b - 192) * 256 + buf[i++]! + 192;
      else if (b === 255) { len = buf.readUInt32BE(i); i += 4; }
      else throw new Error('partial body lengths are not supported');
    } else {
      tag = (first >> 2) & 0x0f;
      const lenType = first & 0x03;
      if (lenType === 0) len = buf[i++]!;
      else if (lenType === 1) { len = buf.readUInt16BE(i); i += 2; }
      else if (lenType === 2) { len = buf.readUInt32BE(i); i += 4; }
      else len = buf.length - i;
    }
    if (i + len > buf.length) throw new Error('truncated OpenPGP packet');
    out.push({ tag, body: Buffer.from(buf.subarray(i, i + len)) });
    i += len;
  }
  return out;
}

export function dearmor(armored: string): Buffer {
  const m = /-----BEGIN PGP [^-]+-----([A-Za-z0-9+/=\s]+?)-----END PGP/.exec(armored);
  if (!m) throw new Error('no PGP armor block found');
  const b64 = m[1]!.replace(/=[A-Za-z0-9+/]{4}\s*$/, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

function readMpi(buf: Buffer, offset: number): { bytes: Buffer; next: number } {
  const bits = buf.readUInt16BE(offset);
  const byteLen = Math.ceil(bits / 8);
  return { bytes: Buffer.from(buf.subarray(offset + 2, offset + 2 + byteLen)), next: offset + 2 + byteLen };
}

export interface PgpPublicKey {
  fingerprint: string; // hex, lowercase
  keyId: string; // last 16 hex chars
  alg: number; // 1 RSA, 22 EdDSA
  createdSeconds: number;
  /** Node public key ready for verification. */
  nodeKey: ReturnType<typeof createPublicKey>;
}

/** Parse all (sub)keys from a public key block, computing v4 fingerprints. */
export function parsePublicKeys(armoredOrDer: string | Buffer): PgpPublicKey[] {
  const buf = typeof armoredOrDer === 'string' ? dearmor(armoredOrDer) : armoredOrDer;
  const keys: PgpPublicKey[] = [];
  for (const pkt of parsePackets(buf)) {
    if (pkt.tag !== 6 && pkt.tag !== 14) continue;
    const body = pkt.body;
    if (body[0] !== 4) continue; // v4 only
    const created = body.readUInt32BE(1);
    const alg = body[5]!;
    let nodeKey: ReturnType<typeof createPublicKey>;
    if (alg === 1 || alg === 2 || alg === 3) {
      const n = readMpi(body, 6);
      const e = readMpi(body, n.next);
      nodeKey = createPublicKey({
        format: 'jwk',
        key: { kty: 'RSA', n: n.bytes.toString('base64url'), e: e.bytes.toString('base64url') },
      });
    } else if (alg === 22) {
      // OID (length-prefixed), then EC point MPI (0x40 || 32-byte native point)
      const oidLen = body[6]!;
      const point = readMpi(body, 7 + oidLen);
      if (point.bytes[0] !== 0x40) continue;
      nodeKey = createPublicKey({
        format: 'jwk',
        key: { kty: 'OKP', crv: 'Ed25519', x: point.bytes.subarray(1).toString('base64url') },
      });
    } else continue;
    const fprInput = Buffer.concat([Buffer.from([0x99, body.length >> 8, body.length & 0xff]), body]);
    const fingerprint = createHash('sha1').update(fprInput).digest('hex');
    keys.push({ fingerprint, keyId: fingerprint.slice(-16), alg, createdSeconds: created, nodeKey });
  }
  return keys;
}

const HASH_ALG: Record<number, { node: string; name: 'sha256' | 'sha512' }> = {
  8: { node: 'RSA-SHA256', name: 'sha256' },
  10: { node: 'RSA-SHA512', name: 'sha512' },
};

export interface PgpVerifyResult {
  valid: boolean;
  keyId: string | null;
  fingerprint: string | null;
  detail: string;
}

/**
 * Verify a detached OpenPGP signature over `data` with one of `keys`
 * (selected by the signature's issuer subpacket). When `requireFingerprint`
 * is given, the signing (sub)key must match it exactly.
 */
export function verifyPgpSignature(
  data: Buffer,
  signatureArmoredOrDer: string | Buffer,
  keys: PgpPublicKey[],
  requireFingerprint?: string,
): PgpVerifyResult {
  try {
    const sigBuf = typeof signatureArmoredOrDer === 'string' ? dearmor(signatureArmoredOrDer) : signatureArmoredOrDer;
    const sigPkt = parsePackets(sigBuf).find((p) => p.tag === 2);
    if (!sigPkt) return { valid: false, keyId: null, fingerprint: null, detail: 'no signature packet' };
    const b = sigPkt.body;
    if (b[0] !== 4) return { valid: false, keyId: null, fingerprint: null, detail: `signature version ${b[0]} unsupported` };
    const sigType = b[1]!;
    const pubAlg = b[2]!;
    const hashAlg = b[3]!;
    const hashedLen = b.readUInt16BE(4);
    const hashedStart = 0; // signature input starts at the version byte
    const hashedEnd = 6 + hashedLen;
    let i = hashedEnd;
    const unhashedLen = b.readUInt16BE(i);
    i += 2;
    const unhashed = b.subarray(i, i + unhashedLen);
    i += unhashedLen;
    const hashPrefix = b.subarray(i, i + 2);
    i += 2;

    // find issuer fingerprint (33) / keyid (16) in both subpacket areas
    let issuerFpr = '';
    let issuerKeyId = '';
    for (const area of [b.subarray(6, hashedEnd), unhashed]) {
      let j = 0;
      while (j < area.length) {
        let len = area[j++]!;
        if (len === 255) { len = area.readUInt32BE(j); j += 4; }
        else if (len >= 192) { len = (len - 192) * 256 + area[j++]! + 192; }
        const type = area[j++]!;
        const value = area.subarray(j, j + len - 1);
        if (type === 16 && value.length === 8) issuerKeyId = Buffer.from(value).toString('hex');
        if (type === 33 && value.length >= 21) issuerFpr = Buffer.from(value.subarray(1)).toString('hex');
        j += len - 1;
      }
    }
    const key = keys.find(
      (k) => (issuerFpr && k.fingerprint === issuerFpr.toLowerCase()) || (issuerKeyId && k.keyId === issuerKeyId.toLowerCase()),
    );
    if (!key) return { valid: false, keyId: issuerKeyId || null, fingerprint: issuerFpr || null, detail: 'signing key not in the pinned key set' };
    if (requireFingerprint && key.fingerprint !== requireFingerprint.toLowerCase()) {
      return { valid: false, keyId: key.keyId, fingerprint: key.fingerprint, detail: 'signing key fingerprint does not match the pinned platform key' };
    }
    const hash = HASH_ALG[hashAlg];
    if (!hash) return { valid: false, keyId: key.keyId, fingerprint: key.fingerprint, detail: `hash algorithm ${hashAlg} unsupported` };
    const trailer = Buffer.alloc(6);
    trailer[0] = 0x04;
    trailer[1] = 0xff;
    trailer.writeUInt32BE(hashedEnd - hashedStart, 2);
    const digest = createHash(hash.name).update(data).update(b.subarray(hashedStart, hashedEnd)).update(trailer).digest();
    if (!digest.subarray(0, 2).equals(hashPrefix)) {
      return { valid: false, keyId: key.keyId, fingerprint: key.fingerprint, detail: 'hash prefix mismatch' };
    }
    let ok = false;
    if (pubAlg === 1 || pubAlg === 2 || pubAlg === 3) {
      const s = readMpi(b, i);
      // OpenPGP RSA signs PKCS#1 v1.5 over the DigestInfo of the hash of
      // (data || hashed area || trailer). Node's verifier hashes its input
      // itself, so feed the identical byte stream.
      const v2 = createVerify(hash.node);
      v2.update(data);
      v2.update(b.subarray(hashedStart, hashedEnd));
      v2.update(trailer);
      v2.end();
      ok = v2.verify(key.nodeKey, s.bytes);
    } else if (pubAlg === 22) {
      const r = readMpi(b, i);
      const s = readMpi(b, r.next);
      const sig = Buffer.concat([r.bytes.subarray(r.bytes[0] === 0x40 ? 1 : 0), s.bytes]);
      ok = sig.length === 64 && cryptoVerify(null, digest, key.nodeKey, sig);
    } else {
      return { valid: false, keyId: key.keyId, fingerprint: key.fingerprint, detail: `public key algorithm ${pubAlg} unsupported` };
    }
    return {
      valid: ok && sigType === 0x00,
      keyId: key.keyId,
      fingerprint: key.fingerprint,
      detail: ok ? `OpenPGP signature verified (key ${key.keyId})` : 'OpenPGP signature does not verify',
    };
  } catch (e) {
    return { valid: false, keyId: null, fingerprint: null, detail: (e as Error).message };
  }
}
