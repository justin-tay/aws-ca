export interface BasicCredentials {
  username: string;
  password: string;
}

/** Parses `Authorization: Basic <base64(user:password)>`. Anything else is `undefined`. */
export function parseBasicAuthorization(header: string | undefined): BasicCredentials | undefined {
  if (header === undefined) {
    return undefined;
  }
  const match = /^Basic\s+([A-Za-z0-9+/]+=*)\s*$/i.exec(header);
  if (!match) {
    return undefined;
  }
  const decoded = Buffer.from(match[1], 'base64').toString('utf8');
  const separator = decoded.indexOf(':');
  if (separator <= 0) {
    return undefined;
  }
  return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
}
