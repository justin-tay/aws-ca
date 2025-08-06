import { PutParameterCommand } from '@aws-sdk/client-ssm';
import { getSSMClient } from './getSSMClient';
import { getConfig } from './getConfig';

export async function saveParameter(
  parameterName: string,
  parameterValue: string,
) {
  const client = getSSMClient();

  const { parameterKmsKeyId: keyId } = getConfig();

  const putParameterCommand = new PutParameterCommand({
    Name: parameterName,
    Value: parameterValue,
    Type: 'SecureString',
    Overwrite: true,
    KeyId: keyId,
  });
  return await client.send(putParameterCommand);
}
