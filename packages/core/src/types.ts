/**
 * Core type definitions for OpenAuth
 * @module types
 */

/** Valid credential types supported by the auth system */
export type CredentialType = "password" | "oauth" | "magic_link";

/** Access and refresh token pair */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

/** PKCE (Proof Key for Code Exchange) challenge data */
export interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

/** Validation rules for passwords and emails */
export interface ValidationRules {
  passwordMinLength?: number;
  passwordRequireUppercase?: boolean;
  passwordRequireNumbers?: boolean;
  passwordRequireSymbols?: boolean;
  emailDomainWhitelist?: string[];
}

/** Core user object */
export interface User {
  id: string;
  email: string;
  emailVerifiedAt?: Date;
  active: boolean;
  metadata?: Record<string, any>;
  createdAt: Date;
}

/** Authentication credential */
export interface Credential {
  userId: string;
  type: CredentialType;
  identifier: string;
  credential: string;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

/** User session data */
export interface Session {
  id: string;
  userId: string;
  refreshToken?: string;
  lastActive: Date;
  expiresAt: Date;
  createdAt: Date;
  userAgent?: string;
  ipAddress?: string;
  metadata?: Record<string, any>;
}

/** Refresh token information */
export interface RefreshToken {
  token: string;
  userId: string;
  sessionId: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
}

/** Verification token for email or password reset */
export interface VerificationToken {
  identifier: string;
  token: string;
  type: "email" | "password_reset";
  expiresAt: Date;
  createdAt: Date;
  metadata?: Record<string, any>;
}

/** Map of available authentication events */
export interface AuthEventMap {
  "user.created": { user: User };
  "user.deleted": { userId: string };
  "user.login": { user: User; session: Session };
  "user.logout": { user: User; session: Session };
  "user.verified": { user: User };
  "token.refresh": { user: User; oldToken: string; newToken: string };
  "session.created": { user: User; session: Session };
  "session.deleted": { sessionId: string };
}

/** Event emitter interface for auth events */
export interface AuthEvents {
  on<K extends keyof AuthEventMap>(
    event: K,
    handler: (payload: AuthEventMap[K]) => void
  ): void;

  emit<K extends keyof AuthEventMap>(event: K, payload: AuthEventMap[K]): void;
}

/** Platform-agnostic cryptographic operations */
export interface CryptoAdapter {
  /** Generate cryptographically secure random bytes */
  randomBytes(size: number): Uint8Array;

  /** Hash data with a salt */
  hash(data: string, salt: string): Promise<string>;

  /** Verify hashed data */
  verifyHash(data: string, hash: string): Promise<boolean>;

  /** Generate PKCE challenge/verifier pair */
  generatePKCEChallenge(): Promise<PKCEChallenge>;

  /** Verify PKCE challenge */
  verifyPKCEChallenge(verifier: string, challenge: string): Promise<boolean>;
}

/** Core database operations interface */
export interface DatabaseAdapter {
  // User operations
  createUser(email: string, metadata?: Record<string, any>): Promise<User>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;
  updateUser(id: string, data: Partial<User>): Promise<User>;
  deleteUser(id: string): Promise<void>;
  createUsers(emails: string[]): Promise<User[]>;
  setUserMetadata(id: string, metadata: Record<string, any>): Promise<void>;

  // Credential operations
  createCredential(
    userId: string,
    type: CredentialType,
    identifier: string,
    credential: string,
    metadata?: Record<string, any>
  ): Promise<void>;
  getCredential(
    userId: string,
    type: CredentialType
  ): Promise<Credential | null>;
  updateCredential(
    userId: string,
    type: CredentialType,
    credential: string
  ): Promise<void>;
  deleteCredentials(userId: string): Promise<void>;

  // Session operations
  createSession(
    userId: string,
    refreshToken: string,
    metadata?: {
      userAgent?: string;
      ipAddress?: string;
      metadata?: Record<string, any>;
    }
  ): Promise<Session>;
  getSession(id: string): Promise<Session | null>;
  updateSessionActivity(id: string): Promise<void>;
  deleteSession(id: string): Promise<void>;
  getUserSessions(userId: string): Promise<Session[]>;
  deleteSessions(userId: string): Promise<void>;

  // Refresh token operations
  createRefreshToken(
    sessionId: string,
    userId: string,
    token: string,
    expiresAt: Date
  ): Promise<RefreshToken>;
  getRefreshToken(token: string): Promise<RefreshToken | null>;
  revokeRefreshToken(token: string): Promise<void>;
  revokeUserRefreshTokens(userId: string): Promise<void>;

  // Verification operations
  createVerificationToken(
    identifier: string,
    token: string,
    type: "email" | "password_reset",
    expiresAt: Date,
    metadata?: Record<string, any>
  ): Promise<void>;
  useVerificationToken(identifier: string, token: string): Promise<boolean>;

  // Transaction support
  transaction<T>(callback: (trx: DatabaseAdapter) => Promise<T>): Promise<T>;
}

/** Authentication configuration options */
export interface AuthConfig {
  /** Secret key for signing tokens */
  secret: string;
  /** Access token expiry in seconds */
  accessTokenExpiry?: number;
  /** Refresh token expiry in seconds */
  refreshTokenExpiry?: number;
  /** Session expiry in seconds */
  sessionExpiry?: number;
  /** Use secure cookies */
  secureCookies?: boolean;
  /** Custom crypto implementation */
  crypto?: CryptoAdapter;
  /** Password and email validation rules */
  validation?: ValidationRules;
  /** Event handlers */
  events?: AuthEvents;
}

/** Result of authentication operations */
export interface AuthResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
  session?: Session;
}

/** Result of token refresh operations */
export interface RefreshResult {
  success: boolean;
  tokens?: TokenPair;
  error?: string;
}
