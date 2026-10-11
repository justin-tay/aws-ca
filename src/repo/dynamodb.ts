import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
  type QueryCommandInput,
} from '@aws-sdk/lib-dynamodb';
import { canonicalSerial } from '../ca';
import type { KeyRef } from '../keystore';
import { TABLE_SCHEMA, keys } from './schema';
import {
  RepositoryError,
  type CaRecord,
  type CaRepository,
  type CertificateProfile,
  type CertificateRecord,
  type OperationalCertificateRecord,
  type Page,
  type ScepChallengeConsumption,
  type ScepChallengeRecord,
} from './types';

type Item = Record<string, unknown>;

const DAY_SECONDS = 24 * 60 * 60;

export interface DynamoCaRepositoryOptions {
  client: DynamoDBDocumentClient;
  tableName: string;
  /** How long after expiry a certificate record is kept before DynamoDB's TTL removes it. Default 90. */
  retentionAfterExpiryDays?: number;
}

/** A document client that drops `undefined` attributes, as this repository expects. */
export function createDocumentClient(
  client: DynamoDBClient = new DynamoDBClient({}),
): DynamoDBDocumentClient {
  return DynamoDBDocumentClient.from(client, { marshallOptions: { removeUndefinedValues: true } });
}

const isConditionFailure = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  'name' in error &&
  error.name === 'ConditionalCheckFailedException';

const iso = (value: Date): string => value.toISOString();
const epoch = (value: Date): number => Math.floor(value.getTime() / 1000);

function encodeToken(key: Record<string, unknown> | undefined): string | undefined {
  return key === undefined ? undefined : Buffer.from(JSON.stringify(key)).toString('base64url');
}

function decodeToken(token: string | undefined): Record<string, unknown> | undefined {
  if (token === undefined) {
    return undefined;
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.from(token, 'base64url').toString());
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new Error('The page token is not valid.');
}

// ---- items ----------------------------------------------------------------

function caToItem(record: CaRecord): Item {
  return {
    ...keys.ca(record.label),
    type: 'ca',
    label: record.label,
    subject: record.subject,
    certificatePem: record.certificatePem,
    keyRef: record.keyRef,
    ...(record.parent === undefined ? {} : { parent: record.parent }),
    crlNumber: record.crlNumber,
    createdAt: iso(record.createdAt),
  };
}

function caFromItem(item: Item): CaRecord {
  return {
    label: item.label as string,
    subject: item.subject as string,
    certificatePem: item.certificatePem as string,
    keyRef: item.keyRef as KeyRef,
    ...(item.parent === undefined ? {} : { parent: item.parent as string }),
    crlNumber: item.crlNumber as number,
    createdAt: new Date(item.createdAt as string),
  };
}

function certificateToItem(record: CertificateRecord, retentionSeconds: number): Item {
  const serial = canonicalSerial(record.serialNumber);
  return {
    ...keys.certificate(record.caLabel, serial),
    ...keys.owner(record.owner, record.subject, serial),
    type: 'certificate',
    caLabel: record.caLabel,
    serialNumber: serial,
    subject: record.subject,
    owner: record.owner,
    profile: record.profile,
    notBefore: iso(record.notBefore),
    notAfter: iso(record.notAfter),
    notAfterEpoch: epoch(record.notAfter),
    certificateDer: Buffer.from(record.certificateDer).toString('base64'),
    status: record.status,
    [TABLE_SCHEMA.ttlAttribute]: epoch(record.notAfter) + retentionSeconds,
  };
}

function certificateFromItem(item: Item): CertificateRecord {
  return {
    caLabel: item.caLabel as string,
    serialNumber: item.serialNumber as string,
    subject: item.subject as string,
    owner: item.owner as string,
    profile: item.profile as CertificateProfile,
    notBefore: new Date(item.notBefore as string),
    notAfter: new Date(item.notAfter as string),
    certificateDer: new Uint8Array(Buffer.from(item.certificateDer as string, 'base64')),
    status: item.status as CertificateRecord['status'],
    ...(item.revokedAt === undefined ? {} : { revokedAt: new Date(item.revokedAt as string) }),
    ...(item.revocationReason === undefined ? {} : { revocationReason: item.revocationReason as number }),
  };
}

function operationalToItem(record: OperationalCertificateRecord): Item {
  return {
    ...keys.operational(record.caLabel, record.sequence),
    type: 'operational',
    caLabel: record.caLabel,
    sequence: record.sequence,
    certificatePem: record.certificatePem,
    keyRef: record.keyRef,
    notAfter: iso(record.notAfter),
    active: record.active,
  };
}

function operationalFromItem(item: Item): OperationalCertificateRecord {
  return {
    caLabel: item.caLabel as string,
    sequence: item.sequence as number,
    certificatePem: item.certificatePem as string,
    keyRef: item.keyRef as KeyRef,
    notAfter: new Date(item.notAfter as string),
    active: item.active as boolean,
  };
}

function challengeToItem(record: ScepChallengeRecord): Item {
  return {
    ...keys.scepChallenge(record.caLabel, record.hash),
    type: 'scep-challenge',
    caLabel: record.caLabel,
    hash: record.hash,
    ...(record.commonName === undefined ? {} : { commonName: record.commonName }),
    createdBy: record.createdBy,
    createdAt: iso(record.createdAt),
    expiresAt: iso(record.expiresAt),
    expiresAtEpoch: epoch(record.expiresAt),
    // DynamoDB removes it some time after it has expired; `expiresAtEpoch` is what is enforced.
    [TABLE_SCHEMA.ttlAttribute]: epoch(record.expiresAt) + 60,
  };
}

function challengeFromItem(item: Item): ScepChallengeRecord {
  return {
    caLabel: item.caLabel as string,
    hash: item.hash as string,
    ...(item.commonName === undefined ? {} : { commonName: item.commonName as string }),
    createdBy: item.createdBy as string,
    createdAt: new Date(item.createdAt as string),
    expiresAt: new Date(item.expiresAt as string),
  };
}

// ---- repository -------------------------------------------------------------

export class DynamoCaRepository implements CaRepository {
  private readonly client: DynamoDBDocumentClient;
  private readonly tableName: string;
  private readonly retentionSeconds: number;

  constructor(options: DynamoCaRepositoryOptions) {
    this.client = options.client;
    this.tableName = options.tableName;
    this.retentionSeconds = (options.retentionAfterExpiryDays ?? 90) * DAY_SECONDS;
  }

  private async get(key: { pk: string; sk: string }): Promise<Item | undefined> {
    const response = await this.client.send(
      new GetCommand({ TableName: this.tableName, Key: key, ConsistentRead: true }),
    );
    return response.Item;
  }

  /** Creates an item, failing with `already-exists` if the key is taken. */
  private async putNew(item: Item, what: string): Promise<void> {
    try {
      await this.client.send(
        new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: 'attribute_not_exists(pk)',
        }),
      );
    } catch (error) {
      if (isConditionFailure(error)) {
        throw new RepositoryError('already-exists', `${what} already exists.`);
      }
      throw error;
    }
  }

  async createCa(record: CaRecord): Promise<void> {
    await this.putNew(caToItem(record), `The CA ${record.label}`);
  }

  async getCa(label: string): Promise<CaRecord | undefined> {
    const item = await this.get(keys.ca(label));
    return item ? caFromItem(item) : undefined;
  }

  async putCertificate(record: CertificateRecord): Promise<void> {
    if (record.status !== 'valid') {
      throw new Error('A certificate is stored as valid; revoke it separately.');
    }
    await this.putNew(
      certificateToItem(record, this.retentionSeconds),
      `Serial ${record.serialNumber} under ${record.caLabel}`,
    );
  }

  async getCertificate(caLabel: string, serialNumber: string): Promise<CertificateRecord | undefined> {
    const item = await this.get(keys.certificate(caLabel, serialNumber));
    return item ? certificateFromItem(item) : undefined;
  }

  async listCertificatesByOwner(
    owner: string,
    options: { subject?: string; limit?: number; nextToken?: string } = {},
  ): Promise<Page<CertificateRecord>> {
    const { ownerIndex } = TABLE_SCHEMA;
    const input: QueryCommandInput = {
      TableName: this.tableName,
      IndexName: ownerIndex.name,
      KeyConditionExpression:
        options.subject === undefined ? '#pk = :pk' : '#pk = :pk AND begins_with(#sk, :prefix)',
      // DynamoDB rejects a placeholder that the expressions do not use.
      ExpressionAttributeNames: {
        '#pk': ownerIndex.partitionKey,
        ...(options.subject === undefined ? {} : { '#sk': ownerIndex.sortKey }),
      },
      ExpressionAttributeValues: {
        ':pk': keys.ownerPartition(owner),
        ...(options.subject === undefined ? {} : { ':prefix': keys.ownerSubjectPrefix(options.subject) }),
      },
      ...(options.limit === undefined ? {} : { Limit: options.limit }),
      ...(options.nextToken === undefined ? {} : { ExclusiveStartKey: decodeToken(options.nextToken) }),
    };
    const response = await this.client.send(new QueryCommand(input));
    const nextToken = encodeToken(response.LastEvaluatedKey);
    return {
      items: (response.Items ?? []).map((item) => certificateFromItem(item)),
      ...(nextToken === undefined ? {} : { nextToken }),
    };
  }

  async revokeCertificate(
    caLabel: string,
    serialNumber: string,
    revocation: { revokedAt: Date; reason?: number },
  ): Promise<CertificateRecord> {
    const serial = canonicalSerial(serialNumber);
    try {
      const response = await this.client.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: keys.certificate(caLabel, serial),
          UpdateExpression:
            'SET #status = :revoked, revokedAt = :revokedAt, revocationReason = :reason, ' +
            '#revokedPk = :revokedPk, #revokedSk = :revokedSk',
          ConditionExpression: 'attribute_exists(pk) AND #status = :valid',
          ExpressionAttributeNames: {
            '#status': 'status',
            '#revokedPk': TABLE_SCHEMA.revokedIndex.partitionKey,
            '#revokedSk': TABLE_SCHEMA.revokedIndex.sortKey,
          },
          ExpressionAttributeValues: {
            ':revoked': 'revoked',
            ':valid': 'valid',
            ':revokedAt': iso(revocation.revokedAt),
            ':reason': revocation.reason ?? null,
            ...Object.fromEntries(
              Object.entries(keys.revoked(caLabel, serial)).map(([name, value]) => [`:${name}`, value]),
            ),
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      const item = response.Attributes;
      if (!item) {
        throw new Error('DynamoDB returned no attributes for the revoked certificate.');
      }
      if (item.revocationReason === null) {
        delete item.revocationReason;
      }
      return certificateFromItem(item);
    } catch (error) {
      if (!isConditionFailure(error)) {
        throw error;
      }
      const existing = await this.getCertificate(caLabel, serial);
      if (!existing) {
        throw new RepositoryError('not-found', `No certificate ${serial} under ${caLabel}.`, {
          cause: error,
        });
      }
      throw new RepositoryError('already-revoked', `Certificate ${serial} is already revoked.`, {
        cause: error,
      });
    }
  }

  async listRevoked(caLabel: string, options: { notExpiredAt?: Date } = {}): Promise<CertificateRecord[]> {
    const { revokedIndex } = TABLE_SCHEMA;
    const items = await this.queryAll({
      TableName: this.tableName,
      IndexName: revokedIndex.name,
      KeyConditionExpression: '#pk = :pk',
      ...(options.notExpiredAt === undefined ? {} : { FilterExpression: 'notAfterEpoch > :now' }),
      ExpressionAttributeNames: { '#pk': revokedIndex.partitionKey },
      ExpressionAttributeValues: {
        ':pk': keys.revokedPartition(caLabel),
        ...(options.notExpiredAt === undefined ? {} : { ':now': epoch(options.notExpiredAt) }),
      },
    });
    return items.map((item) => certificateFromItem(item));
  }

  /** Follows `LastEvaluatedKey` until the query is exhausted. */
  private async queryAll(input: QueryCommandInput, startKey?: Record<string, unknown>): Promise<Item[]> {
    const response = await this.client.send(
      new QueryCommand({ ...input, ...(startKey === undefined ? {} : { ExclusiveStartKey: startKey }) }),
    );
    const items = response.Items ?? [];
    if (response.LastEvaluatedKey === undefined) {
      return items;
    }
    return [...items, ...(await this.queryAll(input, response.LastEvaluatedKey))];
  }

  async nextCrlNumber(caLabel: string): Promise<number> {
    try {
      const response = await this.client.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: keys.ca(caLabel),
          UpdateExpression: 'ADD crlNumber :one',
          ConditionExpression: 'attribute_exists(pk)',
          ExpressionAttributeValues: { ':one': 1 },
          ReturnValues: 'UPDATED_NEW',
        }),
      );
      return response.Attributes?.crlNumber as number;
    } catch (error) {
      if (isConditionFailure(error)) {
        throw new RepositoryError('not-found', `No CA ${caLabel}.`, { cause: error });
      }
      throw error;
    }
  }

  async publishCrl(caLabel: string, crlNumber: number): Promise<boolean> {
    try {
      await this.client.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: keys.crl(caLabel),
          // `type` is a DynamoDB reserved word, so it goes through a name placeholder.
          UpdateExpression: 'SET #type = :type, publishedNumber = :number, publishedAt = :now',
          ConditionExpression: 'attribute_not_exists(publishedNumber) OR publishedNumber < :number',
          ExpressionAttributeNames: { '#type': 'type' },
          ExpressionAttributeValues: { ':type': 'crl', ':number': crlNumber, ':now': iso(new Date()) },
        }),
      );
      return true;
    } catch (error) {
      if (isConditionFailure(error)) {
        return false;
      }
      throw error;
    }
  }

  async getPublishedCrlNumber(caLabel: string): Promise<number | undefined> {
    const item = await this.get(keys.crl(caLabel));
    return item?.publishedNumber as number | undefined;
  }

  async putOperationalCertificate(record: OperationalCertificateRecord): Promise<void> {
    await this.putNew(
      operationalToItem(record),
      `Operational certificate ${record.sequence} of ${record.caLabel}`,
    );
  }

  async listOperationalCertificates(caLabel: string): Promise<OperationalCertificateRecord[]> {
    const response = await this.client.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
        ExpressionAttributeValues: { ':pk': keys.ca(caLabel).pk, ':prefix': keys.operationalPrefix },
        ConsistentRead: true,
        ScanIndexForward: true,
      }),
    );
    return (response.Items ?? []).map((item) => operationalFromItem(item));
  }

  async setOperationalCertificateActive(caLabel: string, sequence: number, active: boolean): Promise<void> {
    try {
      await this.client.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: keys.operational(caLabel, sequence),
          UpdateExpression: 'SET active = :active',
          ConditionExpression: 'attribute_exists(pk)',
          ExpressionAttributeValues: { ':active': active },
        }),
      );
    } catch (error) {
      if (isConditionFailure(error)) {
        throw new RepositoryError('not-found', `No operational certificate ${sequence}.`, { cause: error });
      }
      throw error;
    }
  }

  async putScepChallenge(
    record: ScepChallengeRecord,
    options: { maxOutstanding: number; now: Date },
  ): Promise<void> {
    // Expired items linger until DynamoDB's TTL sweeps them, so they are filtered out of the count.
    let outstanding = 0;
    let startKey: Record<string, unknown> | undefined;
    do {
      // oxlint-disable-next-line no-await-in-loop
      const response = await this.client.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
          FilterExpression: 'expiresAtEpoch > :now',
          ExpressionAttributeValues: {
            ':pk': keys.ca(record.caLabel).pk,
            ':prefix': keys.scepChallengePrefix,
            ':now': epoch(options.now),
          },
          Select: 'COUNT',
          ConsistentRead: true,
          ...(startKey === undefined ? {} : { ExclusiveStartKey: startKey }),
        }),
      );
      outstanding += response.Count ?? 0;
      startKey = response.LastEvaluatedKey;
    } while (startKey !== undefined);
    if (outstanding >= options.maxOutstanding) {
      throw new RepositoryError(
        'limit-reached',
        `Too many SCEP challenges are outstanding for ${record.caLabel}.`,
      );
    }
    await this.putNew(challengeToItem(record), 'The SCEP challenge');
  }

  async consumeScepChallenge(
    caLabel: string,
    hash: string,
    options: { commonName: string; now: Date },
  ): Promise<ScepChallengeConsumption> {
    try {
      const response = await this.client.send(
        new DeleteCommand({
          TableName: this.tableName,
          Key: keys.scepChallenge(caLabel, hash),
          ConditionExpression:
            'attribute_exists(pk) AND expiresAtEpoch > :now AND ' +
            '(attribute_not_exists(commonName) OR commonName = :commonName)',
          ExpressionAttributeValues: { ':now': epoch(options.now), ':commonName': options.commonName },
          ReturnValues: 'ALL_OLD',
        }),
      );
      if (!response.Attributes) {
        return { consumed: false, reason: 'unknown' };
      }
      return { consumed: true, record: challengeFromItem(response.Attributes) };
    } catch (error) {
      if (!isConditionFailure(error)) {
        throw error;
      }
      // Say why, for the log: the condition failed, so look at what is there.
      const item = await this.get(keys.scepChallenge(caLabel, hash));
      if (!item) {
        return { consumed: false, reason: 'unknown' };
      }
      return {
        consumed: false,
        reason: (item.expiresAtEpoch as number) <= epoch(options.now) ? 'expired' : 'bound',
      };
    }
  }
}
