import { getConfig } from './getConfig';

export function getPassword(hash: string) {
  return `${hash}${getConfig().pepper}`;
}
