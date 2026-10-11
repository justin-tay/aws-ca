import { randomBytes } from 'node:crypto';

/** The generation of a stored key: a short random suffix, so a replaced key never reuses a name. */
export const GENERATION = /^[a-z0-9]{4,32}$/;

export const newGeneration = (): string => randomBytes(5).toString('hex');
