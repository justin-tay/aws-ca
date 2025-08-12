import { JsonName, Name, X509Certificate } from '@peculiar/x509';
import crypto from 'crypto';
import { createCa } from './createCa';
import { createCsr } from './createCsr';
import { signCertificate } from './signCertificate';
import { getConfig } from './getConfig';

export interface CreateCaHierarchyParams {
  rootCa: {
    name: string | JsonName | Name;
    validity: number;
  };
  subCa: {
    name: string | JsonName | Name;
    validity: number;
    crlDistributionPoint?: string;
    ocsp?: string;
  };
}
export interface CreateCaHierarchyResult {
  rootCa: {
    certificate: X509Certificate;
  };
  subCa: {
    certificate: X509Certificate;
  };
}

export async function createCaHierarchy(
  params: CreateCaHierarchyParams,
): Promise<CreateCaHierarchyResult> {
  const { rootCa, subCa } = params;

  const alg = getConfig().keyAlgorithm;
  const caKeys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
  const rootCaResult = await createCa({
    name: rootCa.name,
    keys: caKeys,
    validity: rootCa.validity,
  });

  const subCaKeys = await crypto.subtle.generateKey(alg, true, [
    'sign',
    'verify',
  ]);

  const subCaCsr = await createCsr({
    name: subCa.name,
    keys: subCaKeys,
  });

  const subCaResult = await signCertificate({
    csr: subCaCsr.csr,
    profile: 'certificate_authority',
    ca: rootCaResult.certificate,
    validity: subCa.validity,
    crlDistributionPoint: subCa.crlDistributionPoint,
    ocsp: subCa.ocsp,
  });

  subCaResult.certificate.privateKey = subCaKeys.privateKey;

  return {
    rootCa: rootCaResult,
    subCa: subCaResult,
  };
}
