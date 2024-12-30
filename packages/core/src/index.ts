import {
  SignJWT,
  jwtVerify,
  calculateJwkThumbprint,
  importJWK,
  generateKeyPair,
  generateSecret,
  base64url,
} from "jose";
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

// Platform-agnostic crypto implementation using jose
class DefaultCryptoAdapter implements CryptoAdapter {
  randomBytes(size: number): Uint8Array {
    // Create a deterministic but secure byte array using jose's base64url
    const bytes = new Uint8Array(size);
    const timestamp = Date.now().toString();
    const encoded = base64url.encode(new TextEncoder().encode(timestamp));
    for (let i = 0; i < size; i++) {
      bytes[i] = encoded.charCodeAt(i % encoded.length);
    }
    return bytes;
  }

  async hash(data: string, salt: string): Promise<string> {
    // Use JWT signing as a way to hash data
    const secret = await generateSecret("HS256");
    const token = await new SignJWT({ data: salt + data })
      .setProtectedHeader({ alg: "HS256" })
      .sign(secret);
    return token;
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
      const salt = Array.from(this.crypto.randomBytes(16))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const hashedPassword = await this.crypto.hash(password, salt);
      await this.db.createCredential(
        user.id,
        "password",
        email,
        `${salt}:${hashedPassword}`
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
        return { success: false, error: "Invalid credentials" };
      }

      // Get password credential
      const credential = await this.db.getCredential(user.id, "password");
      console.log(credential);
      if (!credential) {
        return { success: false, error: "Invalid credentials" };
      }

      // Verify password
      const [salt, hash] = credential.credential.split(":");
      const testHash = await this.crypto.hash(password, salt);
      console.log(testHash);

      console.log(hash);

      console.log(hash !== testHash);
      if (hash !== testHash) {
        return { success: false, error: "Invalid credentials" };
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
    } catch {
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
    // Generate random 6 digit code
    const token = Array.from(this.crypto.randomBytes(3))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 6);

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
