import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import type { 
  AuthConfig,
  AuthResult,
  DatabaseAdapter,
  User,
  Credential
} from './types';

export * from './types';
export * from './adapters/postgres';

/**
 * Core authentication class that handles all auth operations
 */
export class Auth {
  private secret: Uint8Array;
  private tokenExpiry: number;
  private secureCookies: boolean;

  constructor(
    private db: DatabaseAdapter,
    config: AuthConfig
  ) {
    this.secret = new TextEncoder().encode(config.secret);
    this.tokenExpiry = config.tokenExpiry || 24 * 60 * 60; // 24 hours default
    this.secureCookies = config.secureCookies ?? true;
  }

  /**
   * Register a new user with email/password
   */
  async register(email: string, password: string): Promise<AuthResult> {
    try {
      // Check if user exists
      const existing = await this.db.getUserByEmail(email);
      if (existing) {
        return { success: false, error: 'User already exists' };
      }

      // Create user
      const user = await this.db.createUser(email);

      // Hash password and create credential
      const hashedPassword = await this.hashPassword(password);
      await this.db.createCredential(
        user.id,
        'password',
        email,
        hashedPassword
      );

      // Generate session token
      const token = await this.generateToken(user);

      return { success: true, token };
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Registration failed' 
      };
    }
  }

  /**
   * Login with email/password
   */
  async login(email: string, password: string): Promise<AuthResult> {
    try {
      // Get user
      const user = await this.db.getUserByEmail(email);
      if (!user) {
        return { success: false, error: 'Invalid credentials' };
      }

      // Get password credential
      const credential = await this.db.getCredential(user.id, 'password');
      if (!credential) {
        return { success: false, error: 'Invalid credentials' };
      }

      // Verify password
      const isValid = await this.verifyPassword(credential.credential, password);
      if (!isValid) {
        return { success: false, error: 'Invalid credentials' };
      }

      // Generate session token
      const token = await this.generateToken(user);

      return { success: true, token };
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Login failed' 
      };
    }
  }

  /**
   * Verify a JWT token
   */
  async verifyToken(token: string): Promise<User | null> {
    try {
      const { payload } = await jwtVerify(token, this.secret);
      if (!payload.sub) return null;

      const user = await this.db.getUserById(payload.sub);
      return user;
    } catch {
      return null;
    }
  }

  /**
   * Generate a verification token for email/phone verification
   */
  async generateVerificationToken(identifier: string): Promise<string> {
    // Generate random 6 digit code
    const token = randomBytes(3).toString('hex').slice(0, 6);
    
    // Store verification token
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await this.db.createVerificationToken(identifier, token, expiresAt);

    return token;
  }

  /**
   * Verify a verification token
   */
  async verifyVerificationToken(identifier: string, token: string): Promise<boolean> {
    return this.db.useVerificationToken(identifier, token);
  }

  /**
   * Helper to hash passwords
   */
  private async hashPassword(password: string): Promise<string> {
    const salt = randomBytes(16).toString('hex');
    const hash = createHash('sha256')
      .update(salt + password)
      .digest('hex');
    return `${salt}:${hash}`;
  }

  /**
   * Helper to verify passwords
   */
  private async verifyPassword(hashedPassword: string, password: string): Promise<boolean> {
    const [salt, hash] = hashedPassword.split(':');
    const testHash = createHash('sha256')
      .update(salt + password)
      .digest('hex');
    return hash === testHash;
  }

  /**
   * Helper to generate JWT tokens
   */
  private async generateToken(user: User): Promise<string> {
    const token = await new SignJWT({ email: user.email })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime(`${this.tokenExpiry}s`)
      .sign(this.secret);

    return token;
  }
}
