export interface AuthenticatedUser {
  /** The canonical user name; certificates are bound to this, not to what the client typed. */
  username: string;
  groups: string[];
}

export type AuthFailureCode = 'rate-limited' | 'unavailable';

/** Thrown when authentication could not be decided (as opposed to the credentials being wrong). */
export class AuthError extends Error {
  constructor(
    readonly code: AuthFailureCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'AuthError';
  }
}

export interface Authenticator {
  /** Returns the user, or `undefined` when the credentials are wrong. Throws {@link AuthError} otherwise. */
  authenticate(username: string, password: string): Promise<AuthenticatedUser | undefined>;
}
