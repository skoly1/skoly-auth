import { PoolConfig } from 'pg';

/**
 * Core type definitions for OpenAuth
 * @module types
 */
/** Valid credential types supported by the auth system */
type CredentialType = "password" | "oauth" | "magic_link";
/** Access and refresh token pair */
interface TokenPair {
    accessToken: string;
    refreshToken: string;
}
/** PKCE (Proof Key for Code Exchange) challenge data */
interface PKCEChallenge {
    codeVerifier: string;
    codeChallenge: string;
    codeChallengeMethod: "S256";
}
/** Validation rules for passwords and emails */
interface ValidationRules {
    passwordMinLength?: number;
    passwordRequireUppercase?: boolean;
    passwordRequireNumbers?: boolean;
    passwordRequireSymbols?: boolean;
    emailDomainWhitelist?: string[];
}
/** Core user object */
interface User {
    id: string;
    email: string;
    emailVerifiedAt?: Date;
    active: boolean;
    metadata?: Record<string, any>;
    createdAt: Date;
}
/** Authentication credential */
interface Credential {
    userId: string;
    type: CredentialType;
    identifier: string;
    credential: string;
    metadata?: Record<string, any>;
    createdAt: Date;
    updatedAt: Date;
}
/** User session data */
interface Session {
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
interface RefreshToken {
    token: string;
    userId: string;
    sessionId: string;
    expiresAt: Date;
    createdAt: Date;
    revokedAt?: Date;
}
/** Verification token for email or password reset */
interface VerificationToken {
    identifier: string;
    token: string;
    type: "email" | "password_reset";
    expiresAt: Date;
    createdAt: Date;
    metadata?: Record<string, any>;
}
/** Map of available authentication events */
interface AuthEventMap {
    "user.created": {
        user: User;
    };
    "user.deleted": {
        userId: string;
    };
    "user.login": {
        user: User;
        session: Session;
    };
    "user.logout": {
        user: User;
        session: Session;
    };
    "user.verified": {
        user: User;
    };
    "token.refresh": {
        user: User;
        oldToken: string;
        newToken: string;
    };
    "session.created": {
        user: User;
        session: Session;
    };
    "session.deleted": {
        sessionId: string;
    };
}
/** Event emitter interface for auth events */
interface AuthEvents {
    on<K extends keyof AuthEventMap>(event: K, handler: (payload: AuthEventMap[K]) => void): void;
    emit<K extends keyof AuthEventMap>(event: K, payload: AuthEventMap[K]): void;
}
/** Platform-agnostic cryptographic operations */
interface CryptoAdapter {
    /** Generate cryptographically secure random bytes */
    randomBytes(size: number): Uint8Array;
    /** Hash data with a salt */
    hash(data: string, salt: string): Promise<string>;
    /** Generate PKCE challenge/verifier pair */
    generatePKCEChallenge(): Promise<PKCEChallenge>;
    /** Verify PKCE challenge */
    verifyPKCEChallenge(verifier: string, challenge: string): Promise<boolean>;
}
/** Core database operations interface */
interface DatabaseAdapter {
    createUser(email: string, metadata?: Record<string, any>): Promise<User>;
    getUserById(id: string): Promise<User | null>;
    getUserByEmail(email: string): Promise<User | null>;
    updateUser(id: string, data: Partial<User>): Promise<User>;
    deleteUser(id: string): Promise<void>;
    createUsers(emails: string[]): Promise<User[]>;
    setUserMetadata(id: string, metadata: Record<string, any>): Promise<void>;
    createCredential(userId: string, type: CredentialType, identifier: string, credential: string, metadata?: Record<string, any>): Promise<void>;
    getCredential(userId: string, type: CredentialType): Promise<Credential | null>;
    updateCredential(userId: string, type: CredentialType, credential: string): Promise<void>;
    deleteCredentials(userId: string): Promise<void>;
    createSession(userId: string, refreshToken: string, metadata?: {
        userAgent?: string;
        ipAddress?: string;
        metadata?: Record<string, any>;
    }): Promise<Session>;
    getSession(id: string): Promise<Session | null>;
    updateSessionActivity(id: string): Promise<void>;
    deleteSession(id: string): Promise<void>;
    getUserSessions(userId: string): Promise<Session[]>;
    deleteSessions(userId: string): Promise<void>;
    createRefreshToken(sessionId: string, userId: string, token: string, expiresAt: Date): Promise<RefreshToken>;
    getRefreshToken(token: string): Promise<RefreshToken | null>;
    revokeRefreshToken(token: string): Promise<void>;
    revokeUserRefreshTokens(userId: string): Promise<void>;
    createVerificationToken(identifier: string, token: string, type: "email" | "password_reset", expiresAt: Date, metadata?: Record<string, any>): Promise<void>;
    useVerificationToken(identifier: string, token: string): Promise<boolean>;
    transaction<T>(callback: (trx: DatabaseAdapter) => Promise<T>): Promise<T>;
}
/** Authentication configuration options */
interface AuthConfig {
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
interface AuthResult {
    success: boolean;
    accessToken?: string;
    refreshToken?: string;
    error?: string;
    session?: Session;
}
/** Result of token refresh operations */
interface RefreshResult {
    success: boolean;
    tokens?: TokenPair;
    error?: string;
}

/**
 * PostgreSQL implementation of the DatabaseAdapter interface
 */
declare class PostgresAdapter implements DatabaseAdapter {
    private pool;
    constructor(config: PoolConfig);
    /**
     * Initialize database with required tables
     */
    init(): Promise<void>;
    createUser(email: string, metadata?: Record<string, any>): Promise<User>;
    createUsers(emails: string[]): Promise<User[]>;
    getUserById(id: string): Promise<User | null>;
    getUserByEmail(email: string): Promise<User | null>;
    updateUser(id: string, data: Partial<User>): Promise<User>;
    setUserMetadata(id: string, metadata: Record<string, any>): Promise<void>;
    deleteCredentials(userId: string): Promise<void>;
    deleteSessions(userId: string): Promise<void>;
    transaction<T>(callback: (trx: DatabaseAdapter) => Promise<T>): Promise<T>;
    deleteUser(id: string): Promise<void>;
    createCredential(userId: string, type: string, identifier: string, credential: string): Promise<void>;
    getCredential(userId: string, type: string): Promise<Credential | null>;
    updateCredential(userId: string, type: string, credential: string): Promise<void>;
    createSession(userId: string, refreshToken: string, metadata?: {
        userAgent?: string;
        ipAddress?: string;
    }): Promise<Session>;
    getSession(id: string): Promise<Session | null>;
    updateSessionActivity(id: string): Promise<void>;
    getUserSessions(userId: string): Promise<Session[]>;
    createRefreshToken(sessionId: string, userId: string, token: string, expiresAt: Date): Promise<RefreshToken>;
    getRefreshToken(token: string): Promise<RefreshToken | null>;
    revokeRefreshToken(token: string): Promise<void>;
    revokeUserRefreshTokens(userId: string): Promise<void>;
    deleteSession(id: string): Promise<void>;
    createVerificationToken(identifier: string, token: string, type: "email" | "password_reset", expiresAt: Date, metadata?: Record<string, any>): Promise<void>;
    useVerificationToken(identifier: string, token: string): Promise<boolean>;
    /**
     * Close database connection
     */
    close(): Promise<void>;
}

/**
 * Core authentication class that handles all auth operations
 */
declare class Auth {
    private db;
    private secret;
    private accessTokenExpiry;
    private refreshTokenExpiry;
    private sessionExpiry;
    private secureCookies;
    private crypto;
    constructor(db: DatabaseAdapter, config: AuthConfig);
    /**
     * Register a new user with email/password
     */
    register(email: string, password: string, metadata?: {
        userAgent?: string;
        ipAddress?: string;
        userData?: Record<string, any>;
    }): Promise<AuthResult>;
    /**
     * Login with email/password
     */
    login(email: string, password: string, metadata?: {
        userAgent?: string;
        ipAddress?: string;
    }): Promise<AuthResult>;
    /**
     * Verify an access token
     */
    verifyToken(token: string): Promise<User | null>;
    /**
     * Refresh an access token using a refresh token
     */
    refreshToken(refreshToken: string): Promise<RefreshResult>;
    /**
     * Logout user by revoking their refresh token
     */
    logout(refreshToken: string): Promise<void>;
    /**
     * Logout user from all devices by revoking all refresh tokens
     */
    logoutAll(userId: string): Promise<void>;
    /**
     * Generate a verification token for email/phone verification
     */
    generateVerificationToken(identifier: string, type?: "email" | "password_reset", metadata?: Record<string, any>): Promise<string>;
    /**
     * Verify a verification token
     */
    verifyVerificationToken(identifier: string, token: string): Promise<boolean>;
    /**
     * Helper to generate access and refresh tokens
     */
    private generateTokenPair;
    /**
     * Helper to create a new session with refresh token
     */
    private createSession;
}

export { Auth, type AuthConfig, type AuthEventMap, type AuthEvents, type AuthResult, type Credential, type CredentialType, type CryptoAdapter, type DatabaseAdapter, type PKCEChallenge, PostgresAdapter, type RefreshResult, type RefreshToken, type Session, type TokenPair, type User, type ValidationRules, type VerificationToken };
