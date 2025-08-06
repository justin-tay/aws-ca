import { GetParameterCommand } from '@aws-sdk/client-ssm';
import { getSSMClient } from './getSSMClient';

export async function loadParameter(parameterName: string) {
  const client = getSSMClient();
  const getParameterCommand = new GetParameterCommand({
    Name: parameterName,
    WithDecryption: true,
  });
  return await client.send(getParameterCommand);
}
