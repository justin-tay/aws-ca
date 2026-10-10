import {
  DeleteParameterCommand,
  GetParameterCommand,
  PutParameterCommand,
  SSMClient,
  type PutParameterCommandInput,
} from '@aws-sdk/client-ssm';
import {
  CreateSecretCommand,
  DeleteSecretCommand,
  GetSecretValueCommand,
  SecretsManagerClient,
  type CreateSecretCommandInput,
} from '@aws-sdk/client-secrets-manager';
import { mockClient, type AwsClientStub } from 'aws-sdk-client-mock';

const awsError = (name: string): Error => Object.assign(new Error(name), { name });

export interface FakeSsm {
  client: SSMClient;
  mock: AwsClientStub<SSMClient>;
  /** The parameters currently stored, by name. */
  parameters: Map<string, PutParameterCommandInput>;
}

/** An SSM client backed by a map: `PutParameter`, `GetParameter` and `DeleteParameter` really work. */
export function fakeSsm(): FakeSsm {
  const parameters = new Map<string, PutParameterCommandInput>();
  const mock = mockClient(SSMClient);
  mock.on(PutParameterCommand).callsFake((input: PutParameterCommandInput) => {
    if (input.Name === undefined) {
      throw awsError('ValidationException');
    }
    if (input.Overwrite !== true && parameters.has(input.Name)) {
      throw awsError('ParameterAlreadyExists');
    }
    parameters.set(input.Name, input);
    return { Version: 1 };
  });
  mock.on(GetParameterCommand).callsFake((input: { Name?: string }) => {
    const found = input.Name === undefined ? undefined : parameters.get(input.Name);
    if (!found) {
      throw awsError('ParameterNotFound');
    }
    return { Parameter: { Name: found.Name, Value: found.Value, Type: found.Type } };
  });
  mock.on(DeleteParameterCommand).callsFake((input: { Name?: string }) => {
    if (input.Name === undefined || !parameters.delete(input.Name)) {
      throw awsError('ParameterNotFound');
    }
    return {};
  });
  return { client: new SSMClient({ region: 'ap-southeast-1' }), mock, parameters };
}

export interface FakeSecrets {
  client: SecretsManagerClient;
  mock: AwsClientStub<SecretsManagerClient>;
  secrets: Map<string, CreateSecretCommandInput>;
}

export function fakeSecrets(): FakeSecrets {
  const secrets = new Map<string, CreateSecretCommandInput>();
  const mock = mockClient(SecretsManagerClient);
  mock.on(CreateSecretCommand).callsFake((input: CreateSecretCommandInput) => {
    if (input.Name === undefined) {
      throw awsError('ValidationException');
    }
    if (secrets.has(input.Name)) {
      throw awsError('ResourceExistsException');
    }
    secrets.set(input.Name, input);
    return { Name: input.Name };
  });
  mock.on(GetSecretValueCommand).callsFake((input: { SecretId?: string }) => {
    const found = input.SecretId === undefined ? undefined : secrets.get(input.SecretId);
    if (!found) {
      throw awsError('ResourceNotFoundException');
    }
    return { Name: found.Name, SecretString: found.SecretString };
  });
  mock.on(DeleteSecretCommand).callsFake((input: { SecretId?: string }) => {
    if (input.SecretId === undefined || !secrets.delete(input.SecretId)) {
      throw awsError('ResourceNotFoundException');
    }
    return {};
  });
  return { client: new SecretsManagerClient({ region: 'ap-southeast-1' }), mock, secrets };
}

export { awsError };
