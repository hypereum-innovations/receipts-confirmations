// SPDX-License-Identifier: Apache-2.0
/**
 * Gitsign / Sigstore keyless Git commit signature verification.
 *
 * Parses raw Git commit objects, extracts the `gpgsig` header (CMS/PKCS#7
 * SignedData carrying a Fulcio ephemeral X.509 certificate), reconstructs the
 * canonical commit payload (without the `gpgsig` header block), verifies the
 * cryptographic CMS signature over the commit payload, extracts and validates
 * the Fulcio OIDC identity (SAN URI/email) and OIDC Issuer extension
 * (OID 1.3.6.1.4.1.57264.1.1 / 1.3.6.1.4.1.57264.1.8), chains the leaf
 * certificate to a pinned Fulcio CA root, and verifies that the signature and
 * certificate are anchored in a transparency log (Signed Entry Timestamp)
 * whose integratedTime falls within the ephemeral certificate's validity window.
 */
import {
  X509Certificate,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import {
  der,
  derExplicit,
  derGeneralizedTime,
  derInt,
  derNull,
  derOctetString,
  derOid,
  derSeq,
  derSet,
  oidToString,
  parseDer,
  type DerNode,
} from '../core/asn1.js';
import { cborEncode } from '../core/cbor.js';
import { digestOf } from '../core/capsule.js';
import type { Observation } from './connectors/index.js';

export const OID_FULCIO_ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';
export const OID_FULCIO_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_CONTENT_TYPE_ATTR = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST_ATTR = '1.2.840.113549.1.9.4';
const OID_SIGNING_TIME_ATTR = '1.2.840.113549.1.9.5';
const OID_ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';

const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();
const sha256Hex = (b: Buffer): string => sha256(b).toString('hex');

export interface ParsedGitCommit {
  /** Canonical commit bytes signed by Git (everything except the gpgsig header block). */
  payload: Buffer;
  /** Unindented ASCII-armored signature from the gpgsig header. */
  signatureArmored: string;
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export interface GitsignLogEntry {
  logId: string;
  logIndex: number;
  /** Unix timestamp in seconds when the entry was integrated into the transparency log. */
  integratedTime: number;
  certFingerprintSha256: string;
  signatureSha256: string;
  commitPayloadSha256: string;
  /** Base64 signature over canonical JSON of the log entry fields (Rekor-style SET). */
  setSignature: string;
}

export interface GitsignVerifyResult {
  valid: boolean;
  identityUri: string | null;
  oidcIssuer: string | null;
  oidcIssuerOid: string | null;
  certFingerprintSha256: string | null;
  integratedTime: number | null;
  commitPayloadSha256: string | null;
  detail: string;
}

/**
 * Parse a raw Git commit object and extract its `gpgsig` header and canonical signed payload.
 */
export function parseGitSignedCommit(rawCommit: string): ParsedGitCommit {
  const norm = rawCommit.replace(/\r\n/g, '\n');
  const sep = norm.indexOf('\n\n');
  if (sep < 0) throw new Error('Git commit object has no header/body separator');
  const headerBlock = norm.slice(0, sep);
  const message = norm.slice(sep + 2);
  const headerLines = headerBlock.split('\n');

  const keptHeaderLines: string[] = [];
  const sigLines: string[] = [];
  let inGpgSig = false;
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';

  for (const line of headerLines) {
    if (inGpgSig) {
      if (line.startsWith(' ')) {
        sigLines.push(line.slice(1));
        continue;
      }
      inGpgSig = false;
    }
    if (line.startsWith('gpgsig ')) {
      inGpgSig = true;
      sigLines.push(line.slice('gpgsig '.length));
      continue;
    }
    keptHeaderLines.push(line);
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7).trim();
    else if (line.startsWith('committer ')) committer = line.slice(10).trim();
  }

  if (sigLines.length === 0) {
    throw new Error('Git commit contains no gpgsig header');
  }

  const canonicalCommit = `${keptHeaderLines.join('\n')}\n\n${message}`;
  return {
    payload: Buffer.from(canonicalCommit, 'utf8'),
    signatureArmored: sigLines.join('\n'),
    tree,
    parents,
    author,
    committer,
    message,
  };
}

function algId(oid: string, params: Buffer | null = derNull()): Buffer {
  return derSeq(params ? [derOid(oid), params] : [derOid(oid)]);
}

function extractIssuerNameDer(certDer: Buffer): Buffer {
  const cert = parseDer(certDer);
  const tbs = cert.children![0]!;
  let i = tbs.children![0]!.tag === 0xa0 ? 1 : 0;
  i += 2; // serial, signature algorithm
  return tbs.children![i]!.raw;
}

function extractSubjectNameDer(certDer: Buffer): Buffer {
  const cert = parseDer(certDer);
  const tbs = cert.children![0]!;
  let i = tbs.children![0]!.tag === 0xa0 ? 1 : 0;
  i += 4; // serial, signature algorithm, issuer, validity
  return tbs.children![i]!.raw;
}

/**
 * Issue a short-lived Fulcio-style X.509 v3 certificate (supporting EC P-256 and RSA keys)
 * carrying a SAN URI identity and the Sigstore OIDC Issuer extension (1.3.6.1.4.1.57264.1.1 / .1.8).
 */
export function issueFulcioEphemeralCert(opts: {
  caCertPem: string;
  caPrivateKey: KeyObject | string;
  subjectPublicKey: KeyObject | string;
  identityUri: string;
  oidcIssuer: string;
  issuerOid?: typeof OID_FULCIO_ISSUER_V1 | typeof OID_FULCIO_ISSUER_V2;
  notBefore?: Date;
  notAfter?: Date;
}): {
  certificatePem: string;
  fingerprintSha256: string;
  notBefore: Date;
  notAfter: Date;
} {
  const caCert = new X509Certificate(opts.caCertPem);
  const caPriv = typeof opts.caPrivateKey === 'string' ? createPrivateKey(opts.caPrivateKey) : opts.caPrivateKey;
  const subPub = typeof opts.subjectPublicKey === 'string' ? createPublicKey(opts.subjectPublicKey) : opts.subjectPublicKey;
  const now = new Date();
  const notBefore = opts.notBefore ?? new Date(now.getTime() - 30_000);
  const notAfter = opts.notAfter ?? new Date(notBefore.getTime() + 10 * 60_000);
  const issuerOid = opts.issuerOid ?? OID_FULCIO_ISSUER_V1;

  const isCaEc = caPriv.asymmetricKeyType === 'ec';
  const sigAlg = isCaEc ? algId(OID_ECDSA_WITH_SHA256, null) : algId(OID_RSA_SHA256, derNull());
  const serialBytes = sha256(Buffer.from(`${opts.identityUri}|${notBefore.toISOString()}`)).subarray(0, 12);
  serialBytes[0] = (serialBytes[0]! & 0x7f) | 0x01;

  const subjectName = derSeq([
    derSet([
      derSeq([
        derOid('2.5.4.3'), // commonName
        der(0x0c, Buffer.from('fulcio-ephemeral-leaf', 'utf8')),
      ]),
    ]),
  ]);

  const spkiDer = Buffer.from(subPub.export({ format: 'der', type: 'spki' }));

  const extBasicConstraints = derSeq([
    derOid('2.5.29.19'),
    der(0x01, Buffer.from([0xff])), // critical = TRUE
    derOctetString(derSeq([])), // cA = FALSE
  ]);
  const extKeyUsage = derSeq([
    derOid('2.5.29.15'),
    der(0x01, Buffer.from([0xff])), // critical = TRUE
    derOctetString(der(0x03, Buffer.from([0x07, 0x80]))), // digitalSignature (bit 0)
  ]);
  const extEku = derSeq([
    derOid('2.5.29.37'),
    derOctetString(derSeq([derOid('1.3.6.1.5.5.7.3.3')])), // id-kp-codeSigning
  ]);
  // GeneralName: uniformResourceIdentifier [6] IMPLICIT IA5String (tag 0x86)
  const extSan = derSeq([
    derOid('2.5.29.17'),
    derOctetString(derSeq([der(0x86, Buffer.from(opts.identityUri, 'ascii'))])),
  ]);
  const extFulcioIssuer = derSeq([
    derOid(issuerOid),
    derOctetString(der(0x0c, Buffer.from(opts.oidcIssuer, 'utf8'))),
  ]);

  const extensions = derExplicit(
    3,
    derSeq([extBasicConstraints, extKeyUsage, extEku, extSan, extFulcioIssuer]),
  );

  const tbs = derSeq([
    derExplicit(0, derInt(2)), // v3
    derInt(serialBytes),
    sigAlg,
    extractSubjectNameDer(Buffer.from(caCert.raw)),
    derSeq([derGeneralizedTime(notBefore), derGeneralizedTime(notAfter)]),
    subjectName,
    spkiDer,
    extensions,
  ]);

  const sig = cryptoSign('sha256', tbs, caPriv);
  const certDer = derSeq([tbs, sigAlg, der(0x03, Buffer.concat([Buffer.from([0x00]), sig]))]);
  const certificatePem =
    '-----BEGIN CERTIFICATE-----\n' +
    (certDer.toString('base64').match(/.{1,64}/g) ?? []).join('\n') +
    '\n-----END CERTIFICATE-----\n';
  const parsed = new X509Certificate(certDer);
  return {
    certificatePem,
    fingerprintSha256: parsed.fingerprint256.replace(/:/g, '').toLowerCase(),
    notBefore: new Date(parsed.validFrom),
    notAfter: new Date(parsed.validTo),
  };
}

/**
 * Extract Fulcio OIDC identity (from SAN) and OIDC Issuer (from OID 1.3.6.1.4.1.57264.1.1 or .1.8).
 */
export function extractFulcioOidcClaims(cert: X509Certificate): {
  identityUri: string | null;
  oidcIssuer: string | null;
  oidcIssuerOid: string | null;
} {
  const san = cert.subjectAltName ?? '';
  const sanParts = san
    .split(', ')
    .map((s) => s.trim())
    .filter(Boolean);
  let identityUri: string | null = null;
  for (const part of sanParts) {
    if (part.startsWith('URI:')) {
      identityUri = part.slice(4);
      break;
    }
    if (part.startsWith('email:')) {
      identityUri = `mailto:${part.slice(6)}`;
      break;
    }
  }

  let oidcIssuer: string | null = null;
  let oidcIssuerOid: string | null = null;

  const root = parseDer(Buffer.from(cert.raw));
  const tbs = root.children?.[0];
  if (tbs?.children) {
    const extExplicit = tbs.children.find((c) => c.tag === 0xa3);
    const extSeq = extExplicit?.children?.[0];
    for (const ext of extSeq?.children ?? []) {
      if (!ext.children || ext.children.length < 2) continue;
      const oidNode = ext.children[0]!;
      if (oidNode.tag !== 0x06) continue;
      const oid = oidToString(oidNode.content);
      if (oid !== OID_FULCIO_ISSUER_V1 && oid !== OID_FULCIO_ISSUER_V2) continue;
      const valNode = ext.children[ext.children.length - 1]!;
      if (valNode.tag !== 0x04) continue;
      const rawBytes = valNode.content;
      // Fulcio v2 (1.3.6.1.4.1.57264.1.8) and DER-wrapped v1 encode a UTF8String (0x0c) or IA5String (0x16)
      if (rawBytes.length >= 2 && (rawBytes[0] === 0x0c || rawBytes[0] === 0x16)) {
        try {
          const inner = parseDer(rawBytes);
          oidcIssuer = inner.content.toString('utf8');
          oidcIssuerOid = oid;
          break;
        } catch {
          // Fall back to raw UTF-8 string
        }
      }
      oidcIssuer = rawBytes.toString('utf8');
      oidcIssuerOid = oid;
      break;
    }
  }

  return { identityUri, oidcIssuer, oidcIssuerOid };
}

/**
 * Build a detached CMS/PKCS#7 SignedData signature over `payload` using a Fulcio certificate and private key.
 */
export function buildGitsignCmsDer(
  payload: Buffer,
  certPem: string,
  privateKey: KeyObject | string,
  signingTime = new Date(),
): Buffer {
  const priv = typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey;
  const cert = new X509Certificate(certPem);
  const certDer = Buffer.from(cert.raw);
  const contentDigest = sha256(payload);

  const utcStr = signingTime
    .toISOString()
    .slice(2)
    .replace(/[-:]/g, '')
    .replace('T', '')
    .replace(/\.\d{3}/, '');
  const utcTime = der(0x17, Buffer.from(utcStr, 'ascii'));

  const signedAttrsList = [
    derSeq([derOid(OID_CONTENT_TYPE_ATTR), derSet([derOid(OID_DATA)])]),
    derSeq([derOid(OID_SIGNING_TIME_ATTR), derSet([utcTime])]),
    derSeq([derOid(OID_MESSAGE_DIGEST_ATTR), derSet([derOctetString(contentDigest)])]),
  ].sort((a, b) => Buffer.compare(a, b));

  const signedAttrsContent = Buffer.concat(signedAttrsList);
  const attrsForSigning = der(0x31, signedAttrsContent);

  const isEc = priv.asymmetricKeyType === 'ec';
  const sigAlgDer = isEc ? algId(OID_ECDSA_WITH_SHA256, null) : algId(OID_RSA_SHA256, derNull());
  const signature = cryptoSign('sha256', attrsForSigning, priv);

  const issuerAndSerial = derSeq([
    extractIssuerNameDer(certDer),
    derInt(Buffer.from(cert.serialNumber.replace(/:/g, ''), 'hex')),
  ]);

  const signerInfo = derSeq([
    derInt(1),
    issuerAndSerial,
    algId(OID_SHA256),
    der(0xa0, signedAttrsContent),
    sigAlgDer,
    derOctetString(signature),
  ]);

  const encap = derSeq([derOid(OID_DATA)]);
  const signedData = derSeq([
    derInt(1),
    derSet([algId(OID_SHA256)]),
    encap,
    derExplicit(0, certDer),
    derSet([signerInfo]),
  ]);

  return derSeq([derOid(OID_SIGNED_DATA), derExplicit(0, signedData)]);
}

function expectSeq(node: DerNode, what: string): DerNode[] {
  if (node.tag !== 0x30 || !node.children) throw new Error(`CMS: expected SEQUENCE for ${what}`);
  return node.children;
}

export function parseGitsignCmsDer(cmsDer: Buffer): {
  signerCertPem: string;
  signedAttrs: DerNode | null;
  messageDigestAttr: Buffer | null;
  signature: Buffer;
} {
  const contentInfo = expectSeq(parseDer(cmsDer), 'ContentInfo');
  if (oidToString(contentInfo[0]!.content) !== OID_SIGNED_DATA) {
    throw new Error('CMS ContentInfo is not SignedData');
  }
  const signedData = expectSeq(contentInfo[1]!.children![0]!, 'SignedData');
  let idx = 2; // version, digestAlgorithms
  const encap = expectSeq(signedData[idx++]!, 'EncapsulatedContentInfo');
  if (oidToString(encap[0]!.content) !== OID_DATA) {
    throw new Error('CMS eContentType is not id-data');
  }
  let signerCertPem: string | null = null;
  if (signedData[idx]?.tag === 0xa0) {
    const certDer = signedData[idx]!.children![0]!.raw;
    signerCertPem =
      '-----BEGIN CERTIFICATE-----\n' +
      (certDer.toString('base64').match(/.{1,64}/g) ?? []).join('\n') +
      '\n-----END CERTIFICATE-----\n';
    idx++;
  }
  if (!signerCertPem) throw new Error('CMS SignedData carries no embedded Fulcio certificate');

  const signerInfos = signedData[idx]!;
  const signerInfo = expectSeq(signerInfos.children![0]!, 'SignerInfo');
  let si = 3; // version, sid, digestAlgorithm
  let signedAttrs: DerNode | null = null;
  let messageDigestAttr: Buffer | null = null;
  if (signerInfo[si]?.tag === 0xa0) {
    signedAttrs = signerInfo[si++]!;
    for (const attr of signedAttrs.children ?? []) {
      const parts = expectSeq(attr, 'Attribute');
      if (oidToString(parts[0]!.content) === OID_MESSAGE_DIGEST_ATTR) {
        messageDigestAttr = parts[1]!.children![0]!.content;
      }
    }
  }
  si++; // signatureAlgorithm
  const signature = signerInfo[si]!.content;

  return { signerCertPem, signedAttrs, messageDigestAttr, signature };
}

function canonicalLogEntryBytes(entry: Omit<GitsignLogEntry, 'setSignature'>): Buffer {
  return Buffer.from(
    JSON.stringify({
      certFingerprintSha256: entry.certFingerprintSha256.toLowerCase(),
      commitPayloadSha256: entry.commitPayloadSha256.toLowerCase(),
      integratedTime: entry.integratedTime,
      logId: entry.logId,
      logIndex: entry.logIndex,
      signatureSha256: entry.signatureSha256.toLowerCase(),
    }),
    'utf8',
  );
}

/**
 * Sign a Git commit in Gitsign / Sigstore keyless style (CMS `gpgsig` + transparency log SET).
 */
export function signGitCommitGitsign(
  unsignedCommit: string,
  opts: {
    certPem: string;
    privateKey: KeyObject | string;
    logSigner: { privateKey: KeyObject | string; logId?: string };
    integratedTime?: number;
    logIndex?: number;
  },
): { signedCommit: string; logEntry: GitsignLogEntry } {
  const norm = unsignedCommit.replace(/\r\n/g, '\n');
  const sep = norm.indexOf('\n\n');
  if (sep < 0) throw new Error('unsigned Git commit missing header/body separator');
  const headerBlock = norm.slice(0, sep);
  const message = norm.slice(sep + 2);
  const payload = Buffer.from(`${headerBlock}\n\n${message}`, 'utf8');

  const integratedTime = opts.integratedTime ?? Math.floor(Date.now() / 1000);
  const cmsDer = buildGitsignCmsDer(payload, opts.certPem, opts.privateKey, new Date(integratedTime * 1000));
  const parsedCms = parseGitsignCmsDer(cmsDer);
  const b64Lines = cmsDer.toString('base64').match(/.{1,64}/g) ?? [];
  const armored = ['-----BEGIN SIGNED MESSAGE-----', ...b64Lines, '-----END SIGNED MESSAGE-----'];
  const gpgsigHeader = `gpgsig ${armored[0]}\n${armored.slice(1).map((l) => ` ${l}`).join('\n')}`;

  const signedCommit = `${headerBlock}\n${gpgsigHeader}\n\n${message}`;
  const cert = new X509Certificate(opts.certPem);
  const certFingerprintSha256 = cert.fingerprint256.replace(/:/g, '').toLowerCase();
  const signatureSha256 = sha256Hex(parsedCms.signature);
  const commitPayloadSha256 = sha256Hex(payload);
  const logId = opts.logSigner.logId ?? 'rekor.sigstore.local';
  const logIndex = opts.logIndex ?? 1;

  const entryBody = {
    certFingerprintSha256,
    commitPayloadSha256,
    integratedTime,
    logId,
    logIndex,
    signatureSha256,
  };
  const logPriv =
    typeof opts.logSigner.privateKey === 'string'
      ? createPrivateKey(opts.logSigner.privateKey)
      : opts.logSigner.privateKey;
  const setSig =
    logPriv.asymmetricKeyType === 'ed25519'
      ? cryptoSign(null, canonicalLogEntryBytes(entryBody), logPriv)
      : cryptoSign('sha256', canonicalLogEntryBytes(entryBody), logPriv);

  return {
    signedCommit,
    logEntry: {
      ...entryBody,
      setSignature: setSig.toString('base64'),
    },
  };
}

function dearmorSignature(armored: string): Buffer {
  const b64 = armored
    .split(/\r?\n/)
    .filter((l) => !l.startsWith('-----') && l.trim().length > 0)
    .join('');
  return Buffer.from(b64, 'base64');
}

/**
 * Verify a Gitsign-signed Git commit against Fulcio root CAs and a transparency log SET.
 */
export function verifyGitsignCommit(
  rawCommit: string,
  opts: {
    trustedFulcioRootsPem: string[];
    trustedLogPublicKey: KeyObject | string;
    logEntry: GitsignLogEntry;
    expectedOidcIssuer?: string;
    expectedIdentityUri?: string;
  },
): GitsignVerifyResult {
  const fail = (detail: string): GitsignVerifyResult => ({
    valid: false,
    identityUri: null,
    oidcIssuer: null,
    oidcIssuerOid: null,
    certFingerprintSha256: null,
    integratedTime: null,
    commitPayloadSha256: null,
    detail,
  });

  if (!opts.trustedFulcioRootsPem || opts.trustedFulcioRootsPem.length === 0) {
    return fail('no trusted Fulcio roots configured');
  }
  if (!opts.logEntry) {
    return fail('missing transparency log entry');
  }

  let parsedCommit: ParsedGitCommit;
  try {
    parsedCommit = parseGitSignedCommit(rawCommit);
  } catch (e) {
    return fail(`commit parse error: ${(e as Error).message}`);
  }

  let cms: ReturnType<typeof parseGitsignCmsDer>;
  try {
    const cmsDer = dearmorSignature(parsedCommit.signatureArmored);
    cms = parseGitsignCmsDer(cmsDer);
  } catch (e) {
    return fail(`CMS parse error: ${(e as Error).message}`);
  }

  const commitPayloadDigest = sha256(parsedCommit.payload);
  const commitPayloadSha256 = commitPayloadDigest.toString('hex');

  if (!cms.messageDigestAttr || !cms.messageDigestAttr.equals(commitPayloadDigest)) {
    return fail('CMS messageDigest attribute does not match canonical commit payload SHA-256');
  }

  const cert = new X509Certificate(cms.signerCertPem);
  if (cert.ca) {
    return fail('Fulcio signing certificate must not be a CA certificate');
  }

  const chained = opts.trustedFulcioRootsPem.some((rootPem) => {
    try {
      const root = new X509Certificate(rootPem);
      return cert.verify(root.publicKey);
    } catch {
      return false;
    }
  });
  if (!chained) {
    return fail('Fulcio certificate does not chain to any trusted Fulcio root');
  }

  const signedBytes = cms.signedAttrs
    ? Buffer.concat([Buffer.from([0x31]), cms.signedAttrs.raw.subarray(1)])
    : parsedCommit.payload;

  let cmsSigOk = false;
  try {
    cmsSigOk = cryptoVerify('sha256', signedBytes, cert.publicKey, cms.signature);
  } catch {
    cmsSigOk = false;
  }
  if (!cmsSigOk) {
    return fail('CMS cryptographic signature over commit payload failed verification');
  }

  const { identityUri, oidcIssuer, oidcIssuerOid } = extractFulcioOidcClaims(cert);
  if (!identityUri) {
    return fail('Fulcio certificate lacks SAN URI/email identity');
  }
  if (!oidcIssuer || !oidcIssuerOid) {
    return fail('Fulcio certificate lacks OIDC Issuer extension (1.3.6.1.4.1.57264.1.1 / 1.3.6.1.4.1.57264.1.8)');
  }
  if (opts.expectedOidcIssuer && oidcIssuer !== opts.expectedOidcIssuer) {
    return fail(`OIDC issuer "${oidcIssuer}" does not match expected "${opts.expectedOidcIssuer}"`);
  }
  if (opts.expectedIdentityUri && identityUri !== opts.expectedIdentityUri) {
    return fail(`SAN identity "${identityUri}" does not match expected "${opts.expectedIdentityUri}"`);
  }

  const certFingerprintSha256 = cert.fingerprint256.replace(/:/g, '').toLowerCase();
  const signatureSha256 = sha256Hex(cms.signature);
  const le = opts.logEntry;

  if (le.certFingerprintSha256.toLowerCase() !== certFingerprintSha256) {
    return fail('transparency log entry certificate fingerprint mismatch');
  }
  if (le.signatureSha256.toLowerCase() !== signatureSha256) {
    return fail('transparency log entry signature digest mismatch');
  }
  if (le.commitPayloadSha256.toLowerCase() !== commitPayloadSha256) {
    return fail('transparency log entry commit payload digest mismatch');
  }

  const logPub =
    typeof opts.trustedLogPublicKey === 'string'
      ? createPublicKey(opts.trustedLogPublicKey)
      : opts.trustedLogPublicKey;
  const logBytes = canonicalLogEntryBytes(le);
  const setSigBytes = Buffer.from(le.setSignature, 'base64');
  const setOk =
    logPub.asymmetricKeyType === 'ed25519'
      ? cryptoVerify(null, logBytes, logPub, setSigBytes)
      : cryptoVerify('sha256', logBytes, logPub, setSigBytes);
  if (!setOk) {
    return fail('transparency log Signed Entry Timestamp (SET) signature invalid');
  }

  const integratedMs = le.integratedTime * 1000;
  const notBeforeMs = new Date(cert.validFrom).getTime();
  const notAfterMs = new Date(cert.validTo).getTime();
  if (!Number.isFinite(integratedMs) || integratedMs < notBeforeMs || integratedMs > notAfterMs) {
    return fail(
      `transparency log integratedTime (${new Date(integratedMs).toISOString()}) outside Fulcio certificate validity window [${cert.validFrom} .. ${cert.validTo}]`,
    );
  }

  return {
    valid: true,
    identityUri,
    oidcIssuer,
    oidcIssuerOid,
    certFingerprintSha256,
    integratedTime: le.integratedTime,
    commitPayloadSha256,
    detail: `Gitsign commit verified (${identityUri} via ${oidcIssuer}, log index ${le.logIndex})`,
  };
}

/**
 * Build a W2/W1 Confirmation Observation from a Gitsign-signed Git commit.
 */
export function gitsignObservation(
  rawCommit: string,
  commitSha: string,
  opts: {
    trustedFulcioRootsPem: string[];
    trustedLogPublicKey: KeyObject | string;
    logEntry: GitsignLogEntry;
    expectedOidcIssuer?: string;
    expectedIdentityUri?: string;
  },
): Observation {
  const res = verifyGitsignCommit(rawCommit, opts);
  return {
    system: 'pr',
    event: 'gitsign-commit',
    objectId: commitSha,
    state: res.valid ? 'verified' : 'unverified',
    at: res.integratedTime ? new Date(res.integratedTime * 1000).toISOString() : new Date().toISOString(),
    fields: {
      identity: res.identityUri ?? 'none',
      oidc_issuer: res.oidcIssuer ?? 'none',
      cert_fingerprint: res.certFingerprintSha256 ?? 'none',
    },
    evidenceKind: res.valid ? 'gitsign-fulcio-rekor' : 'gitsign-unverified',
    evidenceDigest: digestOf(cborEncode({ commitSha, valid: res.valid, cert: res.certFingerprintSha256 } as never)),
    level: res.valid ? 'W2' : 'W1',
  };
}
