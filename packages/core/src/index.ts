import {
  SignJWT,
  jwtVerify,
  calculateJwkThumbprint,
  importJWK,
  generateKeyPair,
  generateSecret,
  base64url,
} from "jose";
import * as bcrypt from "bcrypt";
import type {
  AuthConfig,
  AuthResult,
  DatabaseAdapter,
  User,
  Credential,
  CryptoAdapter,
  TokenPair,
  RefreshResult,
  PKCEChallenge,
  Session,
} from "./types";

export * from "./types";
export * from "./adapters/postgres";

// Platform-agnostic crypto implementation using jose and bcrypt
class DefaultCryptoAdapter implements CryptoAdapter {
  randomBytes(size: number): Uint8Array {
    // Use crypto.getRandomValues for true randomness
    const bytes = new Uint8Array(size);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  async hash(data: string, salt: string): Promise<string> {
    // Use bcrypt for secure password hashing
    const saltRounds = 10;
    return await bcrypt.hash(data, saltRounds);
  }

  async verifyHash(data: string, hash: string): Promise<boolean> {
    // Use bcrypt to verify hashed passwords
    return await bcrypt.compare(data, hash);
  }

  async generatePKCEChallenge(): Promise<PKCEChallenge> {
    const verifierBytes = this.randomBytes(32);
    const verifier = base64url.encode(verifierBytes);

    // Generate challenge using JWT thumbprint
    const jwk = { kty: "oct", k: verifier, alg: "HS256" };
    const challenge = await calculateJwkThumbprint(jwk);

    return {
      codeVerifier: verifier,
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    };
  }

  async verifyPKCEChallenge(
    verifier: string,
    challenge: string
  ): Promise<boolean> {
    const jwk = { kty: "oct", k: verifier, alg: "HS256" };
    const computedChallenge = await calculateJwkThumbprint(jwk);
    return challenge === computedChallenge;
  }
}

/**
 * Core authentication class that handles all auth operations
 */
export class Auth {
  private secret: Uint8Array;
  private accessTokenExpiry: number;
  private refreshTokenExpiry: number;
  private sessionExpiry: number;
  private secureCookies: boolean;
  private crypto: CryptoAdapter;

  constructor(
    private db: DatabaseAdapter,
    config: AuthConfig
  ) {
    this.secret = new TextEncoder().encode(config.secret);
    this.accessTokenExpiry = config.accessTokenExpiry || 15 * 60; // 15 minutes default
    this.refreshTokenExpiry = config.refreshTokenExpiry || 7 * 24 * 60 * 60; // 7 days default
    this.sessionExpiry = config.sessionExpiry || 30 * 24 * 60 * 60; // 30 days default
    this.secureCookies = config.secureCookies ?? true;
    this.crypto = config.crypto || new DefaultCryptoAdapter();
  }

  /**
   * Register a new user with email/password
   */
  async register(
    email: string,
    password: string,
    metadata?: {
      userAgent?: string;
      ipAddress?: string;
      userData?: Record<string, any>;
    }
  ): Promise<AuthResult> {
    try {
      // Check if user exists
      const existing = await this.db.getUserByEmail(email);
      if (existing) {
        return { success: false, error: "User already exists" };
      }

      // Create user with metadata
      const user = await this.db.createUser(email, metadata?.userData);

      // Hash password and create credential
      const hashedPassword = await this.crypto.hash(password, "");
      await this.db.createCredential(
        user.id,
        "password",
        email,
        hashedPassword
      );

      // Generate tokens and create session
      const tokens = await this.generateTokenPair(user);
      const session = await this.createSession(
        user.id,
        tokens.refreshToken,
        metadata
      );

      return {
        success: true,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        session,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Registration failed",
      };
    }
  }

  /**
   * Login with email/password
   */
  async login(
    email: string,
    password: string,
    metadata?: { userAgent?: string; ipAddress?: string }
  ): Promise<AuthResult> {
    try {
      // Get user
      const user = await this.db.getUserByEmail(email);
      if (!user) {
        return { success: false, error: "Authentication failed" };
      }

      // Get password credential
      const credential = await this.db.getCredential(user.id, "password");
      if (!credential) {
        return { success: false, error: "Authentication failed" };
      }

      // Verify password using bcrypt
      const isValid = await this.crypto.verifyHash(
        password,
        credential.credential
      );
      if (!isValid) {
        return { success: false, error: "Authentication failed" };
      }

      // Generate tokens and create session
      const tokens = await this.generateTokenPair(user);
      const session = await this.createSession(
        user.id,
        tokens.refreshToken,
        metadata
      );

      return {
        success: true,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        session,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Login failed",
      };
    }
  }

  /**
   * Verify an access token
   */
  async verifyToken(token: string): Promise<User | null> {
    try {
      const { payload } = await jwtVerify(token, this.secret);
      if (!payload.sub || payload.type !== "access") return null;

      const user = await this.db.getUserById(payload.sub);
      return user;
    } catch (error) {
      console.error("Token verification failed:", error);
      return null;
    }
  }

  /**
   * Refresh an access token using a refresh token
   */
  async refreshToken(refreshToken: string): Promise<RefreshResult> {
    try {
      // Verify refresh token exists and is not revoked
      const storedToken = await this.db.getRefreshToken(refreshToken);
      if (!storedToken || storedToken.revokedAt) {
        return { success: false, error: "Invalid refresh token" };
      }

      // Check if token is expired
      if (storedToken.expiresAt < new Date()) {
        await this.db.revokeRefreshToken(refreshToken);
        return { success: false, error: "Refresh token expired" };
      }

      // Get user
      const user = await this.db.getUserById(storedToken.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      // Generate new token pair
      const tokens = await this.generateTokenPair(user);

      // Revoke old refresh token and create new one
      await this.db.revokeRefreshToken(refreshToken);
      await this.createSession(user.id, tokens.refreshToken);

      return { success: true, tokens };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Token refresh failed",
      };
    }
  }

  /**
   * Logout user by revoking their refresh token
   */
  async logout(refreshToken: string): Promise<void> {
    await this.db.revokeRefreshToken(refreshToken);
  }

  /**
   * Logout user from all devices by revoking all refresh tokens
   */
  async logoutAll(userId: string): Promise<void> {
    await this.db.revokeUserRefreshTokens(userId);
  }

  /**
   * Generate a verification token for email/phone verification
   */
  async generateVerificationToken(
    identifier: string,
    type: "email" | "password_reset" = "email",
    metadata?: Record<string, any>
  ): Promise<string> {
    // Generate random 6 digit number (100000-999999)
    const randomBytes = this.crypto.randomBytes(4);
    const number =
      (((randomBytes[0] |
        (randomBytes[1] << 8) |
        (randomBytes[2] << 16) |
        ((randomBytes[3] & 0x7f) << 24)) >>>
        0) %
        900000) +
      100000;
    const token = number.toString();

    // Store verification token
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await this.db.createVerificationToken(
      identifier,
      token,
      type,
      expiresAt,
      metadata
    );

    return token;
  }

  /**
   * Verify a verification token
   */
  async verifyVerificationToken(
    identifier: string,
    token: string
  ): Promise<boolean> {
    return this.db.useVerificationToken(identifier, token);
  }

  /**
   * Helper to generate access and refresh tokens
   */
  private async generateTokenPair(user: User): Promise<TokenPair> {
    const accessToken = await new SignJWT({ email: user.email, type: "access" })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime(`${this.accessTokenExpiry}s`)
      .sign(this.secret);

    const refreshToken = Array.from(this.crypto.randomBytes(32))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    return { accessToken, refreshToken };
  }

  /**
   * Helper to create a new session with refresh token
   */
  private async createSession(
    userId: string,
    refreshToken: string,
    metadata?: { userAgent?: string; ipAddress?: string }
  ): Promise<Session> {
    const expiresAt = new Date(Date.now() + this.sessionExpiry * 1000);
    const session = await this.db.createSession(userId, refreshToken, metadata);

    await this.db.createRefreshToken(
      session.id,
      userId,
      refreshToken,
      new Date(Date.now() + this.refreshTokenExpiry * 1000)
    );

    return session;
  }
}
