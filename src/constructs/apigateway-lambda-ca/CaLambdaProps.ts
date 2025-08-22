import KeyStore from './KeyStore';

export interface CaLambdaProps {
  caTableName?: string;
  caIndexTableName?: string;
  rootCaName?: string;
  rootCaKeySecretId?: string;
  rootCaKeyParameterName?: string;
  rootCaCrlBucketName?: string;
  rootCaCrlKey?: string;
  subCaName?: string;
  subCaKeySecretId?: string;
  subCaKeyParameterName?: string;
  subCaCrlBucketName?: string;
  subCaCrlKey?: string;
  keyStore?: KeyStore;
  rsaModulusLength?: number;
  ecCurve?: string;
  pepper?: string;
  secretsManagerKmsKeyId?: string;
  parameterKmsKeyId?: string;
  scepChallengePasswordParameterName?: string;
}
