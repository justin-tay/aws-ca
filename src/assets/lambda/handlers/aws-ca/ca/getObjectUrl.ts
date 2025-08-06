import { getConfig } from './getConfig';

export function getObjectUrl(params: {
  bucketName: string;
  key: string;
  region?: string;
}) {
  const { bucketName, key } = params;
  const region = params.region ?? getConfig().region;
  return `http://${bucketName}.s3.${region}.amazonaws.com/${key}`;
}
