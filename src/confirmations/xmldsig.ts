// SPDX-License-Identifier: Apache-2.0
/**
 * Enveloped XMLDSig verification for network-signed e-invoicing receipts
 * (PEPPOL AS4 message-level responses / BIS 3.0 invoices, SdI FatturaPA)
 * via xml-crypto (MIT), paired with PEPPOL BIS Billing 3.0 Schematron
 * and FatturaPA v1.2.2 XSD structural/semantic validators.
 *
 * Trust is anchored by the caller pinning signer certificates: an
 * embedded KeyInfo certificate is accepted only if it is byte-identical
 * to a pinned one, and the signature must cover the whole document
 * (Reference URI="" with the enveloped-signature transform, or the
 * document root). A valid signature from an unpinned key or over a
 * schema-invalid invoice is NOT W2.
 */
import { X509Certificate } from 'node:crypto';
import { XMLParser } from 'fast-xml-parser';
import { SignedXml } from 'xml-crypto';

export interface XmlSigResult {
  valid: boolean;
  signerSubject: string | null;
  detail: string;
}

export interface SchemaValidationResult {
  valid: boolean;
  errors: string[];
}

function certDer(pemOrB64: string): Buffer {
  const cert = new X509Certificate(pemOrB64.includes('-----BEGIN') ? pemOrB64 : Buffer.from(pemOrB64.replace(/\s/g, ''), 'base64'));
  return Buffer.from(cert.raw);
}

export function verifyXmlSignature(xml: string, pinnedCertPems: string[]): XmlSigResult {
  if (pinnedCertPems.length === 0) return { valid: false, signerSubject: null, detail: 'no pinned signer certificates configured' };
  try {
    const sigs = new SignedXml();
    const sigMatch = /<([A-Za-z0-9_-]*:)?Signature[\s>]/.exec(xml);
    if (!sigMatch) return { valid: false, signerSubject: null, detail: 'no XML Signature element' };
    // Extract the embedded X509Certificate and require it to be pinned.
    const certB64 = /<([A-Za-z0-9_-]*:)?X509Certificate>([^<]+)<\//.exec(xml)?.[2];
    let signingCert: X509Certificate | null = null;
    if (certB64) {
      const embedded = certDer(certB64);
      for (const pinned of pinnedCertPems) {
        if (certDer(pinned).equals(embedded)) {
          signingCert = new X509Certificate(embedded);
          break;
        }
      }
      if (!signingCert) {
        return { valid: false, signerSubject: null, detail: 'embedded signing certificate is not pinned' };
      }
    }
    const keyPem = signingCert
      ? signingCert.toString()
      : pinnedCertPems[0]!;
    const verifier = new SignedXml({ publicCert: keyPem });
    // locate the Signature element textually the way xml-crypto expects
    const nsPrefix = sigMatch[1] ?? '';
    const sigStart = sigMatch.index;
    const sigEndTag = `</${nsPrefix}Signature>`;
    const sigEnd = xml.indexOf(sigEndTag, sigStart);
    if (sigEnd < 0) return { valid: false, signerSubject: null, detail: 'malformed Signature element' };
    void sigs;
    const signatureElement = xml.slice(sigStart, sigEnd + sigEndTag.length);
    verifier.loadSignature(signatureElement);
    // Refuse signatures that do not cover the document (detached/partial
    // references must not mint W2 for content they do not bind).
    const refUris = [...signatureElement.matchAll(/<([A-Za-z0-9_-]*:)?Reference[^>]*\sURI="([^"]*)"/g)].map((m) => m[2]!);
    const coversDocument = refUris.some((u) => u === '' || u.startsWith('#'));
    if (!coversDocument) return { valid: false, signerSubject: null, detail: `signature references do not cover the document: ${refUris.join(',')}` };
    const ok = verifier.checkSignature(xml);
    const subject = signingCert ? signingCert.subject.replace(/\n/g, ', ') : null;
    return ok
      ? { valid: true, signerSubject: subject, detail: `XMLDSig verified${subject ? ` by ${subject}` : ''}` }
      : { valid: false, signerSubject: subject, detail: `signature validation failed: ${(verifier as { validationErrors?: string[] }).validationErrors?.join('; ') ?? 'unknown'}` };
  } catch (e) {
    return { valid: false, signerSubject: null, detail: (e as Error).message };
  }
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
});

function asObj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function asArray<T>(v: T | T[] | undefined | null): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function textOf(v: unknown): string {
  if (typeof v === 'string' || typeof v === 'number') return String(v).trim();
  const o = asObj(v);
  if (o && '#text' in o) return String(o['#text'] ?? '').trim();
  return '';
}

function attrOf(v: unknown, attr: string): string {
  const o = asObj(v);
  return o ? String(o[`@_${attr}`] ?? '').trim() : '';
}

const PEPPOL_CUSTOMIZATION_PREFIX = 'urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0';
const PEPPOL_INVOICE_TYPE_CODES = new Set(['380', '381', '384', '389', '751', '80', '82', '84', '395', '575', '623', '780']);

/**
 * Validate PEPPOL BIS Billing 3.0 Schematron rules (EN 16931 + PEPPOL CIUS):
 * - cbc:CustomizationID (PEPPOL-EN16931-R004)
 * - cbc:ProfileID (PEPPOL-EN16931-R001)
 * - cbc:ID, cbc:IssueDate (YYYY-MM-DD), cbc:InvoiceTypeCode, cbc:DocumentCurrencyCode (ISO 4217)
 * - cac:AccountingSupplierParty & cac:AccountingCustomerParty with cbc:EndpointID[@schemeID]
 * - cac:TaxTotal/cbc:TaxAmount & cac:LegalMonetaryTotal with BR-CO-15
 *   (TaxInclusiveAmount == TaxExclusiveAmount + TaxAmount)
 * - At least one cac:InvoiceLine (BR-16)
 */
export function validatePeppolBis3(xml: string): SchemaValidationResult {
  const errors: string[] = [];
  let parsed: Record<string, unknown>;
  try {
    parsed = asObj(xmlParser.parse(xml)) ?? {};
  } catch (e) {
    return { valid: false, errors: [`XML parse error: ${(e as Error).message}`] };
  }

  const inv =
    asObj(parsed['Invoice']) ??
    asObj(parsed['CreditNote']) ??
    asObj(asObj(parsed['ApplicationResponse'])?.['Invoice']);
  if (!inv) {
    return { valid: false, errors: ['PEPPOL-BIS3: missing Invoice or CreditNote root element'] };
  }

  const customizationId = textOf(inv['CustomizationID']);
  if (!customizationId.startsWith(PEPPOL_CUSTOMIZATION_PREFIX)) {
    errors.push(`PEPPOL-EN16931-R004: invalid or missing cbc:CustomizationID "${customizationId}"`);
  }

  const profileId = textOf(inv['ProfileID']);
  if (!profileId || !/^urn:fdc:peppol\.eu:2017:poacc:billing:\d{2}:1\.0$/.test(profileId)) {
    errors.push(`PEPPOL-EN16931-R001: invalid or missing cbc:ProfileID "${profileId}"`);
  }

  const id = textOf(inv['ID']);
  if (!id) errors.push('BR-02: missing cbc:ID');

  const issueDate = textOf(inv['IssueDate']);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(issueDate)) {
    errors.push(`PEPPOL-EN16931-F001: invalid or missing cbc:IssueDate "${issueDate}"`);
  }

  const typeCode = textOf(inv['InvoiceTypeCode'] ?? inv['CreditNoteTypeCode']);
  if (!PEPPOL_INVOICE_TYPE_CODES.has(typeCode)) {
    errors.push(`BR-04: invalid or missing cbc:InvoiceTypeCode "${typeCode}"`);
  }

  const currency = textOf(inv['DocumentCurrencyCode']);
  if (!/^[A-Z]{3}$/.test(currency)) {
    errors.push(`BR-05: invalid or missing cbc:DocumentCurrencyCode "${currency}"`);
  }

  const supplierPartyObj = asObj(inv['AccountingSupplierParty']);
  const supplierParty = asObj(supplierPartyObj?.['Party']) ?? supplierPartyObj;
  const supplierEndpoint = supplierParty?.['EndpointID'];
  if (!textOf(supplierEndpoint) || !attrOf(supplierEndpoint, 'schemeID')) {
    errors.push('PEPPOL-EN16931-R020: cac:AccountingSupplierParty must contain cbc:EndpointID with @schemeID');
  }

  const customerPartyObj = asObj(inv['AccountingCustomerParty']);
  const customerParty = asObj(customerPartyObj?.['Party']) ?? customerPartyObj;
  const customerEndpoint = customerParty?.['EndpointID'];
  if (!textOf(customerEndpoint) || !attrOf(customerEndpoint, 'schemeID')) {
    errors.push('PEPPOL-EN16931-R010: cac:AccountingCustomerParty must contain cbc:EndpointID with @schemeID');
  }

  const taxTotals = asArray(inv['TaxTotal']).map(asObj).filter((x): x is Record<string, unknown> => x !== null);
  const firstTaxTotal = taxTotals[0];
  const taxAmountStr = textOf(firstTaxTotal?.['TaxAmount']);
  const taxAmount = taxAmountStr !== '' ? Number(taxAmountStr) : NaN;
  if (!firstTaxTotal || !Number.isFinite(taxAmount)) {
    errors.push('BR-CO-14: missing or non-numeric cac:TaxTotal/cbc:TaxAmount');
  }

  const lmt = asObj(inv['LegalMonetaryTotal']);
  if (!lmt) {
    errors.push('BR-DEC: missing cac:LegalMonetaryTotal');
  } else {
    const taxExclStr = textOf(lmt['TaxExclusiveAmount']);
    const taxInclStr = textOf(lmt['TaxInclusiveAmount']);
    const taxExcl = taxExclStr !== '' ? Number(taxExclStr) : NaN;
    const taxIncl = taxInclStr !== '' ? Number(taxInclStr) : NaN;
    if (!Number.isFinite(taxExcl) || !Number.isFinite(taxIncl)) {
      errors.push('BR-CO-13/15: missing or non-numeric TaxExclusiveAmount / TaxInclusiveAmount');
    } else if (Number.isFinite(taxAmount) && Math.abs(taxIncl - (taxExcl + taxAmount)) > 0.005) {
      errors.push(
        `BR-CO-15: TaxInclusiveAmount (${taxIncl.toFixed(2)}) must equal TaxExclusiveAmount (${taxExcl.toFixed(2)}) + TaxAmount (${taxAmount.toFixed(2)})`,
      );
    }
  }

  const lines = asArray(inv['InvoiceLine'] ?? inv['CreditNoteLine']).map(asObj).filter((x): x is Record<string, unknown> => x !== null);
  if (lines.length === 0) {
    errors.push('BR-16: at least one cac:InvoiceLine is required');
  } else {
    for (const [i, line] of lines.entries()) {
      if (!textOf(line['ID'])) errors.push(`BR-21: InvoiceLine[${i}] missing cbc:ID`);
      const lineExt = textOf(line['LineExtensionAmount']);
      if (lineExt === '' || !Number.isFinite(Number(lineExt))) {
        errors.push(`BR-24: InvoiceLine[${i}] missing or non-numeric cbc:LineExtensionAmount`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate FatturaPA XSD v1.2.2 structural and semantic rules:
 * - FatturaElettronica @versione in {FPR12, FPA12}
 * - FatturaElettronicaHeader -> DatiTrasmissione (IdTrasmittente, ProgressivoInvio,
 *   FormatoTrasmissione, CodiceDestinatario), CedentePrestatore (IdFiscaleIVA,
 *   Anagrafica, RegimeFiscale RF01..RF19), CessionarioCommittente
 * - FatturaElettronicaBody -> DatiGeneraliDocumento (TipoDocumento TD01..TD27,
 *   Divisa, Data, Numero), DatiBeniServizi (DettaglioLinee, DatiRiepilogo with
 *   Imposta = AliquotaIVA * ImponibileImporto / 100)
 */
export function validateFatturaPA(xml: string): SchemaValidationResult {
  const errors: string[] = [];
  let parsed: Record<string, unknown>;
  try {
    parsed = asObj(xmlParser.parse(xml)) ?? {};
  } catch (e) {
    return { valid: false, errors: [`XML parse error: ${(e as Error).message}`] };
  }

  const fe =
    asObj(parsed['FatturaElettronica']) ??
    asObj(asObj(parsed['RicevutaConsegna'])?.['FatturaElettronica']);
  if (!fe) {
    return { valid: false, errors: ['FatturaPA: missing FatturaElettronica root element'] };
  }

  const versione = attrOf(fe, 'versione');
  if (versione !== 'FPR12' && versione !== 'FPA12') {
    errors.push(`FatturaPA: invalid or missing @versione "${versione}" (expected FPR12 or FPA12)`);
  }

  const header = asObj(fe['FatturaElettronicaHeader']);
  if (!header) {
    errors.push('FatturaPA: missing FatturaElettronicaHeader');
  } else {
    const dt = asObj(header['DatiTrasmissione']);
    if (!dt) {
      errors.push('FatturaPA: missing DatiTrasmissione');
    } else {
      const idTrasm = asObj(dt['IdTrasmittente']);
      if (!idTrasm || !/^[A-Z]{2}$/.test(textOf(idTrasm['IdPaese'])) || !textOf(idTrasm['IdCodice'])) {
        errors.push('FatturaPA: invalid or missing DatiTrasmissione/IdTrasmittente');
      }
      if (!textOf(dt['ProgressivoInvio'])) {
        errors.push('FatturaPA: missing DatiTrasmissione/ProgressivoInvio');
      }
      const formato = textOf(dt['FormatoTrasmissione']);
      if (formato !== 'FPR12' && formato !== 'FPA12') {
        errors.push(`FatturaPA: invalid DatiTrasmissione/FormatoTrasmissione "${formato}"`);
      } else if (versione && formato !== versione) {
        errors.push(`FatturaPA: FormatoTrasmissione "${formato}" does not match @versione "${versione}"`);
      }
      const codDest = textOf(dt['CodiceDestinatario']);
      if (!/^[A-Z0-9]{6,7}$/.test(codDest)) {
        errors.push(`FatturaPA: invalid DatiTrasmissione/CodiceDestinatario "${codDest}"`);
      }
    }

    const cp = asObj(header['CedentePrestatore']);
    const cpAnag = asObj(cp?.['DatiAnagrafici']) ?? cp;
    if (!cpAnag) {
      errors.push('FatturaPA: missing CedentePrestatore/DatiAnagrafici');
    } else {
      const idIva = asObj(cpAnag['IdFiscaleIVA']);
      if (!idIva || !/^[A-Z]{2}$/.test(textOf(idIva['IdPaese'])) || !textOf(idIva['IdCodice'])) {
        errors.push('FatturaPA: invalid or missing CedentePrestatore IdFiscaleIVA');
      }
      const anag = asObj(cpAnag['Anagrafica']);
      if (!anag || (!textOf(anag['Denominazione']) && !(textOf(anag['Nome']) && textOf(anag['Cognome'])))) {
        errors.push('FatturaPA: invalid or missing CedentePrestatore Anagrafica');
      }
      const rf = textOf(cpAnag['RegimeFiscale']);
      if (!/^RF(0[1-9]|1[0-9])$/.test(rf)) {
        errors.push(`FatturaPA: invalid CedentePrestatore RegimeFiscale "${rf}" (expected RF01..RF19)`);
      }
    }

    const cc = asObj(header['CessionarioCommittente']);
    const ccAnag = asObj(cc?.['DatiAnagrafici']) ?? cc;
    if (!cc || !ccAnag) {
      errors.push('FatturaPA: missing CessionarioCommittente');
    } else {
      const ccIva = asObj(ccAnag['IdFiscaleIVA']);
      const ccCf = textOf(ccAnag['CodiceFiscale']);
      if ((!ccIva || !textOf(ccIva['IdCodice'])) && !ccCf) {
        errors.push('FatturaPA: CessionarioCommittente requires IdFiscaleIVA or CodiceFiscale');
      }
      const anag = asObj(ccAnag['Anagrafica']);
      if (!anag || (!textOf(anag['Denominazione']) && !(textOf(anag['Nome']) && textOf(anag['Cognome'])))) {
        errors.push('FatturaPA: invalid or missing CessionarioCommittente Anagrafica');
      }
    }
  }

  const body = asObj(asArray(fe['FatturaElettronicaBody'])[0]);
  if (!body) {
    errors.push('FatturaPA: missing FatturaElettronicaBody');
  } else {
    const dg = asObj(body['DatiGenerali']);
    const dgd = asObj(dg?.['DatiGeneraliDocumento']) ?? asObj(body['DatiGeneraliDocumento']);
    if (!dgd) {
      errors.push('FatturaPA: missing DatiGeneraliDocumento');
    } else {
      const td = textOf(dgd['TipoDocumento']);
      if (!/^TD(0[1-9]|1[0-9]|2[0-8])$/.test(td)) {
        errors.push(`FatturaPA: invalid TipoDocumento "${td}" (expected TD01..TD28)`);
      }
      const divisa = textOf(dgd['Divisa']);
      if (!/^[A-Z]{3}$/.test(divisa)) {
        errors.push(`FatturaPA: invalid Divisa "${divisa}"`);
      }
      const data = textOf(dgd['Data']);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(data)) {
        errors.push(`FatturaPA: invalid Data "${data}"`);
      }
      if (!textOf(dgd['Numero'])) {
        errors.push('FatturaPA: missing Numero in DatiGeneraliDocumento');
      }
    }

    const dbs = asObj(body['DatiBeniServizi']);
    if (!dbs) {
      errors.push('FatturaPA: missing DatiBeniServizi');
    } else {
      const linee = asArray(dbs['DettaglioLinee']).map(asObj).filter((x): x is Record<string, unknown> => x !== null);
      if (linee.length === 0) {
        errors.push('FatturaPA: DatiBeniServizi requires at least one DettaglioLinee');
      } else {
        for (const [i, l] of linee.entries()) {
          if (!textOf(l['NumeroLinea']) || !textOf(l['Descrizione']) || !textOf(l['PrezzoTotale']) || !textOf(l['AliquotaIVA'])) {
            errors.push(`FatturaPA: DettaglioLinee[${i}] missing required fields`);
          }
        }
      }

      const riepiloghi = asArray(dbs['DatiRiepilogo']).map(asObj).filter((x): x is Record<string, unknown> => x !== null);
      if (riepiloghi.length === 0) {
        errors.push('FatturaPA: DatiBeniServizi requires at least one DatiRiepilogo');
      } else {
        for (const [i, r] of riepiloghi.entries()) {
          const aliq = Number(textOf(r['AliquotaIVA']));
          const impon = Number(textOf(r['ImponibileImporto']));
          const imposta = Number(textOf(r['Imposta']));
          if (!Number.isFinite(aliq) || !Number.isFinite(impon) || !Number.isFinite(imposta)) {
            errors.push(`FatturaPA: DatiRiepilogo[${i}] has non-numeric AliquotaIVA/ImponibileImporto/Imposta`);
          } else {
            const expectedImposta = (aliq * impon) / 100;
            if (Math.abs(imposta - expectedImposta) > 0.01) {
              errors.push(
                `FatturaPA: DatiRiepilogo[${i}] Imposta (${imposta.toFixed(2)}) does not match AliquotaIVA (${aliq.toFixed(2)}) * ImponibileImporto (${impon.toFixed(2)}) / 100 = ${expectedImposta.toFixed(2)}`,
              );
            }
          }
        }
      }
    }
  }

  return { valid: errors.length === 0, errors };
}
