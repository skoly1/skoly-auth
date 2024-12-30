/**
 * Core database types for OpenAuth
 */

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
  expiresAt: Date;
  createdAt: Date;
}

export interface VerificationToken {
  identifier: string;
  token: string;
  expiresAt: Date;
  createdAt: Date;
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
  createSession(userId: string, expiresAt: Date): Promise<Session>;
  getSession(id: string): Promise<Session | null>;
  deleteSession(id: string): Promise<void>;
  
  // Verification operations
  createVerificationToken(identifier: string, token: string, expiresAt: Date): Promise<void>;
  useVerificationToken(identifier: string, token: string): Promise<boolean>;
}

/**
 * Configuration options for auth
 */
export interface AuthConfig {
  secret: string;
  tokenExpiry?: number; // In seconds
  secureCookies?: boolean;
}

/**
 * Result of auth operations
 */
export interface AuthResult {
  success: boolean;
  token?: string;
  error?: string;
}
