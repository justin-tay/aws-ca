import { X509CrlCreateParams, X509CrlGenerator } from '@peculiar/x509';

export async function createCrl(params: X509CrlCreateParams) {
  return X509CrlGenerator.create(params);
}
