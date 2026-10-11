/**
 * A CA label: the stable identity used in paths, table keys and key names. Lowercase letters, digits
 * and `-`, up to 32 characters, starting with a letter or digit. The configuration is stricter (see
 * `resolveConfig`); everything that reads a label from somewhere else uses this.
 */
export const CA_LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** The same as a regular expression fragment, for route patterns. */
export const CA_LABEL_SEGMENT = '[a-z0-9][a-z0-9-]{0,31}';
