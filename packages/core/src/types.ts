/**
 * Core database types for OpenAuth
 */

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

export interface User {
  id: string;
  email: string;
  createdAt: Date;
}

export interface Credential {
  userId: string;
  type: string; // 'password', 'oauth', etc.
  identifier: string; // email, oauth provider id, etc.
  credential: string; // hashed password, oauth token, etc.
  createdAt: Date;
  updatedAt: Date;
}

export interface Session {
  id: string;
  userId: string;
  refreshToken?: string;
  lastActive: Date;
  expiresAt: Date;
  createdAt: Date;
  userAgent?: string;
  ipAddress?: string;
}

export interface RefreshToken {
  token: string;
  userId: string;
  sessionId: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
}

export interface VerificationToken {
  identifier: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
}

/**
 * Platform agnostic crypto interface that must be implemented
 */
export interface CryptoAdapter {
  // Random bytes generation
  randomBytes(size: number): Uint8Array;
  
  // Hashing
  hash(data: string, salt: string): Promise<string>;
  
  // PKCE
  generatePKCEChallenge(): Promise<PKCEChallenge>;
  verifyPKCEChallenge(verifier: string, challenge: string): Promise<boolean>;
}

/**
 * Database adapter interface that must be implemented
 */
export interface DatabaseAdapter {
  // User operations
  createUser(email: string): Promise<User>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;
  
  // Credential operations  
  createCredential(userId: string, type: string, identifier: string, credential: string): Promise<void>;
  getCredential(userId: string, type: string): Promise<Credential | null>;
  updateCredential(userId: string, type: string, credential: string): Promise<void>;
  
  // Session operations
  createSession(userId: string, refreshToken: string, metadata?: { userAgent?: string; ipAddress?: string }): Promise<Session>;
  getSession(id: string): Promise<Session | null>;
  updateSessionActivity(id: string): Promise<void>;
  deleteSession(id: string): Promise<void>;
  getUserSessions(userId: string): Promise<Session[]>;
  
  // Refresh token operations
  createRefreshToken(sessionId: string, userId: string, token: string, expiresAt: Date): Promise<RefreshToken>;
  getRefreshToken(token: string): Promise<RefreshToken | null>;
  revokeRefreshToken(token: string): Promise<void>;
  revokeUserRefreshTokens(userId: string): Promise<void>;
  
  // Verification operations
  createVerificationToken(identifier: string, token: string, expiresAt: Date): Promise<void>;
  useVerificationToken(identifier: string, token: string): Promise<boolean>;
}

/**
 * Configuration options for auth
 */
export interface AuthConfig {
  secret: string;
  accessTokenExpiry?: number; // In seconds, default 15 minutes
  refreshTokenExpiry?: number; // In seconds, default 7 days
  sessionExpiry?: number; // In seconds, default 30 days
  secureCookies?: boolean;
  crypto?: CryptoAdapter; // Custom crypto implementation
}

/**
 * Result of auth operations
 */
export interface AuthResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
  session?: Session;
}

/**
 * Result of token refresh operations
 */
export interface RefreshResult {
  success: boolean;
  tokens?: TokenPair;
  error?: string;
}
