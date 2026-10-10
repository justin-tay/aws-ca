import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoCaRepository, TABLE_SCHEMA, createDocumentClient } from '../../src/repo';
import { awsError } from '../keystore/fakes';
import { caRecord, certRecord, opsRecord } from './contract';

// The contract suite proves behaviour against the in-memory implementation and, opt-in, against a
// real table. These tests pin the requests the DynamoDB implementation sends: the key layout, the
// condition expressions and the index names, which the contract cannot see.
const dynamo = mockClient(DynamoDBDocumentClient);
const client = createDocumentClient(new DynamoDBClient({ region: 'ap-southeast-1' }));
const repo = new DynamoCaRepository({ client, tableName: 'ca-table' });

beforeEach(() => {
  dynamo.reset();
});

/** The input of the first call recorded for a command. */
const firstInput = (calls: { args: unknown[] }[]): Record<string, unknown> =>
  (calls[0].args[0] as { input: Record<string, unknown> }).input;

describe('key layout', () => {
  it('stores a CA under CA#label / META, only if it is new', async () => {
    dynamo.on(PutCommand).resolves({});
    await repo.createCa(caRecord('issuing', { parent: 'root' }));
    const input = firstInput(dynamo.commandCalls(PutCommand));
    expect(input).toMatchObject({
      TableName: 'ca-table',
      ConditionExpression: 'attribute_not_exists(pk)',
      Item: { pk: 'CA#issuing', sk: 'META', type: 'ca', label: 'issuing', parent: 'root', crlNumber: 0 },
    });
  });

  it('maps a failed condition to already-exists', async () => {
    dynamo.on(PutCommand).rejects(awsError('ConditionalCheckFailedException'));
    await expect(repo.createCa(caRecord('issuing'))).rejects.toMatchObject({ code: 'already-exists' });
  });

  it('lets other failures through unchanged', async () => {
    dynamo.on(PutCommand).rejects(awsError('ProvisionedThroughputExceededException'));
    await expect(repo.createCa(caRecord('issuing'))).rejects.toMatchObject({
      name: 'ProvisionedThroughputExceededException',
    });
  });

  it('stores a certificate with its owner and expiry keys, and a TTL after expiry', async () => {
    dynamo.on(PutCommand).resolves({});
    const record = certRecord('issuing', '00ABC', {
      owner: 'a#b@example.com',
      subject: 'CN=Zoë, O=Ex#ample',
    });
    await repo.putCertificate(record);
    const { Item, ConditionExpression } = firstInput(dynamo.commandCalls(PutCommand)) as {
      Item: Record<string, unknown>;
      ConditionExpression: string;
    };
    expect(ConditionExpression).toBe('attribute_not_exists(pk)');
    expect(Item).toMatchObject({
      pk: 'CA#issuing',
      sk: 'CERT#abc',
      serialNumber: 'abc',
      ownerPk: `OWNER#${encodeURIComponent('a#b@example.com')}`,
      ownerSk: `S#${encodeURIComponent('CN=Zoë, O=Ex#ample')}#abc`,
      status: 'valid',
      certificateDer: Buffer.from(record.certificateDer).toString('base64'),
    });
    const notAfterEpoch = Math.floor(record.notAfter.getTime() / 1000);
    expect(Item.notAfterEpoch).toBe(notAfterEpoch);
    expect(Item[TABLE_SCHEMA.ttlAttribute]).toBe(notAfterEpoch + 90 * 24 * 60 * 60);
    // An unrevoked certificate is not in the sparse revoked index.
    expect(Item).not.toHaveProperty('revokedPk');
  });

  it('keeps expired certificates for the configured retention', async () => {
    dynamo.on(PutCommand).resolves({});
    const short = new DynamoCaRepository({ client, tableName: 't', retentionAfterExpiryDays: 7 });
    const record = certRecord('issuing', 'aa');
    await short.putCertificate(record);
    const { Item } = firstInput(dynamo.commandCalls(PutCommand)) as { Item: Record<string, number> };
    expect(Item.ttl).toBe(Math.floor(record.notAfter.getTime() / 1000) + 7 * 24 * 60 * 60);
  });

  it('stores operational certificates under a sortable, zero padded key', async () => {
    dynamo.on(PutCommand).resolves({});
    await repo.putOperationalCertificate(opsRecord('issuing', 12));
    expect((firstInput(dynamo.commandCalls(PutCommand)) as { Item: unknown }).Item).toMatchObject({
      pk: 'CA#issuing',
      sk: 'OPS#0000000012',
    });
  });
});

describe('reads', () => {
  it('are strongly consistent when they decide something', async () => {
    dynamo.on(GetCommand).resolves({});
    await repo.getCa('issuing');
    await repo.getCertificate('issuing', 'aa');
    await repo.getPublishedCrlNumber('issuing');
    const calls = dynamo.commandCalls(GetCommand);
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call.args[0].input.ConsistentRead).toBe(true);
    }
  });

  it('list operational certificates by prefix, in order, consistently', async () => {
    dynamo.on(QueryCommand).resolves({ Items: [] });
    await repo.listOperationalCertificates('issuing');
    expect(firstInput(dynamo.commandCalls(QueryCommand))).toMatchObject({
      KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
      ExpressionAttributeValues: { ':pk': 'CA#issuing', ':prefix': 'OPS#' },
      ConsistentRead: true,
      ScanIndexForward: true,
    });
  });
});

describe('certificates by owner', () => {
  it('query the owner index, narrowed to a subject by prefix', async () => {
    dynamo.on(QueryCommand).resolves({ Items: [] });
    await repo.listCertificatesByOwner('alice', { subject: 'CN=a', limit: 5 });
    expect(firstInput(dynamo.commandCalls(QueryCommand))).toMatchObject({
      IndexName: TABLE_SCHEMA.ownerIndex.name,
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :prefix)',
      ExpressionAttributeNames: { '#pk': 'ownerPk', '#sk': 'ownerSk' },
      ExpressionAttributeValues: { ':pk': 'OWNER#alice', ':prefix': `S#${encodeURIComponent('CN=a')}#` },
      Limit: 5,
    });
  });

  it('hand back a token for the next page and accept it again', async () => {
    const key = { pk: 'CA#issuing', sk: 'CERT#a3', ownerPk: 'OWNER#alice', ownerSk: 'S#CN%3Dalice#a3' };
    dynamo.on(QueryCommand).resolvesOnce({ Items: [], LastEvaluatedKey: key }).resolvesOnce({ Items: [] });
    const first = await repo.listCertificatesByOwner('alice', { limit: 3 });
    expect(first.nextToken).toBeDefined();
    const second = await repo.listCertificatesByOwner('alice', { limit: 3, nextToken: first.nextToken });
    expect(second.nextToken).toBeUndefined();
    expect(dynamo.commandCalls(QueryCommand)[1].args[0].input.ExclusiveStartKey).toEqual(key);
  });

  it('reject a token that is not one', async () => {
    await expect(repo.listCertificatesByOwner('alice', { nextToken: '!!!' })).rejects.toThrow(/token/);
  });
});

const updated = {
  Attributes: {
    caLabel: 'issuing',
    serialNumber: 'aa',
    subject: 'CN=alice',
    owner: 'alice',
    profile: 'client',
    notBefore: '2026-10-09T00:00:00.000Z',
    notAfter: '2027-01-08T00:00:00.000Z',
    certificateDer: 'AAA=',
    status: 'revoked',
    revokedAt: '2026-10-11T00:00:00.000Z',
    revocationReason: 1,
  },
};

const revokedItem = (serial: string) => ({ ...updated.Attributes, serialNumber: serial });

describe('revocation', () => {
  it('flips a valid certificate and adds it to the revoked index in one conditional update', async () => {
    dynamo.on(UpdateCommand).resolves(updated);
    const result = await repo.revokeCertificate('issuing', '00AA', {
      revokedAt: new Date('2026-10-11T00:00:00Z'),
      reason: 1,
    });
    expect(result).toMatchObject({ status: 'revoked', revocationReason: 1 });
    const input = firstInput(dynamo.commandCalls(UpdateCommand)) as Record<string, unknown> & {
      ExpressionAttributeValues: Record<string, unknown>;
    };
    expect(input).toMatchObject({
      Key: { pk: 'CA#issuing', sk: 'CERT#aa' },
      ConditionExpression: 'attribute_exists(pk) AND #status = :valid',
      ReturnValues: 'ALL_NEW',
    });
    expect(input.ExpressionAttributeValues).toMatchObject({
      ':revokedPk': 'REVOKED#issuing',
      ':revokedSk': 'aa',
      ':valid': 'valid',
      ':revoked': 'revoked',
    });
  });

  it('says not-found when the certificate does not exist', async () => {
    dynamo.on(UpdateCommand).rejects(awsError('ConditionalCheckFailedException'));
    dynamo.on(GetCommand).resolves({});
    await expect(repo.revokeCertificate('issuing', 'aa', { revokedAt: new Date() })).rejects.toMatchObject({
      code: 'not-found',
    });
  });

  it('says already-revoked when it exists but is not valid', async () => {
    dynamo.on(UpdateCommand).rejects(awsError('ConditionalCheckFailedException'));
    dynamo.on(GetCommand).resolves({ Item: updated.Attributes });
    await expect(repo.revokeCertificate('issuing', 'aa', { revokedAt: new Date() })).rejects.toMatchObject({
      code: 'already-revoked',
    });
  });

  it('lists revocations from the sparse index, following every page', async () => {
    dynamo
      .on(QueryCommand)
      .resolvesOnce({ Items: [revokedItem('a1'), revokedItem('a2')], LastEvaluatedKey: { pk: 'x', sk: 'y' } })
      .resolvesOnce({ Items: [revokedItem('a3')] });
    const revoked = await repo.listRevoked('issuing', { notExpiredAt: new Date('2026-10-10T00:00:00Z') });
    expect(revoked.map((cert) => cert.serialNumber)).toEqual(['a1', 'a2', 'a3']);
    const [first, second] = dynamo.commandCalls(QueryCommand).map((call) => call.args[0].input);
    expect(first).toMatchObject({
      IndexName: TABLE_SCHEMA.revokedIndex.name,
      KeyConditionExpression: '#pk = :pk',
      FilterExpression: 'notAfterEpoch > :now',
      ExpressionAttributeValues: { ':pk': 'REVOKED#issuing', ':now': 1_791_590_400 },
    });
    expect(second.ExclusiveStartKey).toEqual({ pk: 'x', sk: 'y' });
  });
});

describe('CRL numbers and publication', () => {
  it('increments atomically on an existing CA', async () => {
    dynamo.on(UpdateCommand).resolves({ Attributes: { crlNumber: 7 } });
    expect(await repo.nextCrlNumber('issuing')).toBe(7);
    expect(firstInput(dynamo.commandCalls(UpdateCommand))).toMatchObject({
      Key: { pk: 'CA#issuing', sk: 'META' },
      UpdateExpression: 'ADD crlNumber :one',
      ConditionExpression: 'attribute_exists(pk)',
      ReturnValues: 'UPDATED_NEW',
    });
  });

  it('reports a missing CA', async () => {
    dynamo.on(UpdateCommand).rejects(awsError('ConditionalCheckFailedException'));
    await expect(repo.nextCrlNumber('issuing')).rejects.toMatchObject({ code: 'not-found' });
  });

  it('publishes only a higher number', async () => {
    dynamo.on(UpdateCommand).resolves({});
    expect(await repo.publishCrl('issuing', 6)).toBe(true);
    expect(firstInput(dynamo.commandCalls(UpdateCommand))).toMatchObject({
      Key: { pk: 'CA#issuing', sk: 'CRL' },
      ConditionExpression: 'attribute_not_exists(publishedNumber) OR publishedNumber < :number',
    });
    dynamo.on(UpdateCommand).rejects(awsError('ConditionalCheckFailedException'));
    expect(await repo.publishCrl('issuing', 5)).toBe(false);
  });
});

describe('item shapes', () => {
  it('reads a CA back from what it wrote', async () => {
    let written: Record<string, unknown> | undefined;
    dynamo.on(PutCommand).callsFake((input: { Item: Record<string, unknown> }) => {
      written = input.Item;
      return {};
    });
    const record = caRecord('issuing', { parent: 'root', crlNumber: 3 });
    await repo.createCa(record);
    dynamo.on(GetCommand).resolves({ Item: written });
    expect(await repo.getCa('issuing')).toEqual(record);
  });
});

// DynamoDB validates expressions strictly, and only the real service says so: a placeholder that is
// defined but unused, a placeholder used but not defined, and a reserved word used as an attribute
// name are all rejected. Both of the first two real-table failures were of this kind and no mock
// noticed. This check applies those rules to every request the repository can send.
describe('every request is a valid DynamoDB expression', () => {
  // Words DynamoDB reserves that this repository's attributes could plausibly collide with.
  const RESERVED = new Set([
    'TYPE',
    'STATUS',
    'NAME',
    'DATA',
    'KEY',
    'VALUE',
    'STATE',
    'TIME',
    'TIMESTAMP',
    'USER',
    'ROLE',
    'SOURCE',
    'TTL',
    'ACTION',
    'COUNT',
  ]);
  const KEYWORDS = new Set([
    'SET',
    'ADD',
    'REMOVE',
    'DELETE',
    'AND',
    'OR',
    'NOT',
    'ATTRIBUTE_EXISTS',
    'ATTRIBUTE_NOT_EXISTS',
    'BEGINS_WITH',
  ]);
  const EXPRESSIONS = [
    'UpdateExpression',
    'ConditionExpression',
    'KeyConditionExpression',
    'FilterExpression',
    'ProjectionExpression',
  ];

  function problemsIn(input: Record<string, unknown>): string[] {
    const text = EXPRESSIONS.map((name) => input[name])
      .filter((value): value is string => typeof value === 'string')
      .join(' ');
    const names = Object.keys((input.ExpressionAttributeNames as Record<string, string> | undefined) ?? {});
    const values = Object.keys(
      (input.ExpressionAttributeValues as Record<string, unknown> | undefined) ?? {},
    );
    const problems: string[] = [];
    for (const name of names) {
      if (!text.includes(name)) problems.push(`unused name ${name}`);
    }
    for (const value of values) {
      if (!text.includes(value)) problems.push(`unused value ${value}`);
    }
    for (const used of text.match(/#\w+/g) ?? []) {
      if (!names.includes(used)) problems.push(`undefined name ${used}`);
    }
    for (const used of text.match(/:\w+/g) ?? []) {
      if (!values.includes(used)) problems.push(`undefined value ${used}`);
    }
    const bare = text.replaceAll(/[#:]\w+/g, ' ').match(/[A-Za-z_]\w*/g) ?? [];
    for (const word of bare) {
      const upper = word.toUpperCase();
      if (!KEYWORDS.has(upper) && RESERVED.has(upper)) problems.push(`reserved word ${word}`);
    }
    return problems;
  }

  it('uses only defined, used placeholders and no reserved word as a bare name', async () => {
    dynamo.on(PutCommand).resolves({});
    dynamo.on(GetCommand).resolves({});
    dynamo.on(QueryCommand).resolves({ Items: [] });
    dynamo.on(UpdateCommand).resolves({ Attributes: { ...updated.Attributes, crlNumber: 1 } });

    await repo.createCa(caRecord('issuing'));
    await repo.getCa('issuing');
    await repo.putCertificate(certRecord('issuing', 'aa'));
    await repo.getCertificate('issuing', 'aa');
    await repo.listCertificatesByOwner('alice');
    await repo.listCertificatesByOwner('alice', { subject: 'CN=alice', limit: 2 });
    await repo.revokeCertificate('issuing', 'aa', { revokedAt: new Date(), reason: 1 });
    await repo.revokeCertificate('issuing', 'aa', { revokedAt: new Date() });
    await repo.listRevoked('issuing');
    await repo.listRevoked('issuing', { notExpiredAt: new Date() });
    await repo.nextCrlNumber('issuing');
    await repo.publishCrl('issuing', 1);
    await repo.getPublishedCrlNumber('issuing');
    await repo.putOperationalCertificate(opsRecord('issuing', 1));
    await repo.listOperationalCertificates('issuing');
    await repo.setOperationalCertificateActive('issuing', 1, true);

    const calls = [PutCommand, GetCommand, QueryCommand, UpdateCommand].flatMap((command) =>
      dynamo
        .commandCalls(command as never)
        .map((call) => (call.args[0] as { input: Record<string, unknown> }).input),
    );
    expect(calls.length).toBeGreaterThanOrEqual(16);
    const problems = calls.flatMap((input) =>
      problemsIn(input).map(
        (problem) =>
          `${String(input.UpdateExpression ?? input.KeyConditionExpression ?? input.ConditionExpression)}: ${problem}`,
      ),
    );
    expect(problems).toEqual([]);
  });

  it('catches the mistakes it exists for', () => {
    expect(problemsIn({ UpdateExpression: 'SET type = :t', ExpressionAttributeValues: { ':t': 1 } })).toEqual(
      ['reserved word type'],
    );
    expect(
      problemsIn({
        KeyConditionExpression: '#pk = :pk',
        ExpressionAttributeNames: { '#pk': 'p', '#sk': 's' },
        ExpressionAttributeValues: { ':pk': 1 },
      }),
    ).toEqual(['unused name #sk']);
    expect(
      problemsIn({ KeyConditionExpression: '#pk = :pk', ExpressionAttributeValues: { ':pk': 1 } }),
    ).toEqual(['undefined name #pk']);
  });
});
