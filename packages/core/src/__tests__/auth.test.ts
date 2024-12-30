import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { Auth } from '../index';
import { PostgresAdapter } from '../adapters/postgres';

describe('Auth', () => {
  let auth: Auth;
  let db: PostgresAdapter;

  beforeAll(async () => {
    // Setup test database
    db = new PostgresAdapter({
      host: 'localhost',
      database: 'openauth',
      user: 'postgres',
      password: ''
    });
    
    await db.init();
    
    auth = new Auth(db, {
      secret: 'test_secret',
      accessTokenExpiry: 900, // 15 minutes
      refreshTokenExpiry: 604800, // 7 days
      sessionExpiry: 2592000, // 30 days
      secureCookies: true
    });
  });

  afterAll(async () => {
    await db.close();
  });

  describe('registration', () => {
    it('should register a new user with metadata', async () => {
      const result = await auth.register('test@example.com', 'password123', {
        userAgent: 'Mozilla/5.0',
        ipAddress: '127.0.0.1',
        userData: { name: 'Test User' }
      });
      expect(result.success).toBe(true);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.session).toBeDefined();
      if (result.session) {
        expect(result.session.userAgent).toBe('Mozilla/5.0');
        expect(result.session.ipAddress).toBe('127.0.0.1');
      }
    });

    it('should not register duplicate email', async () => {
      const result = await auth.register('test@example.com', 'password123');
      expect(result.success).toBe(false);
      expect(result.error).toBe('User already exists');
    });
  });

  describe('login and session management', () => {
    let refreshToken: string;
    let userId: string;

    beforeEach(async () => {
      const email = `user-${Date.now()}@example.com`;
      const result = await auth.register(email, 'password123');
      refreshToken = result.refreshToken!;
      const user = await auth.verifyToken(result.accessToken!);
      userId = user!.id;
    });

    it('should login with correct credentials and create session', async () => {
      const result = await auth.login('test@example.com', 'password123', {
        userAgent: 'Test Browser',
        ipAddress: '192.168.1.1'
      });
      expect(result.success).toBe(true);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.session).toBeDefined();
      if (result.session) {
        expect(result.session.userAgent).toBe('Test Browser');
        expect(result.session.ipAddress).toBe('192.168.1.1');
      }
    });

    it('should refresh access token', async () => {
      const result = await auth.refreshToken(refreshToken);
      expect(result.success).toBe(true);
      expect(result.tokens?.accessToken).toBeDefined();
      expect(result.tokens?.refreshToken).toBeDefined();
    });

    it('should not refresh with invalid token', async () => {
      const result = await auth.refreshToken('invalid-token');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid refresh token');
    });

    it('should logout from single device', async () => {
      await auth.logout(refreshToken);
      const refreshResult = await auth.refreshToken(refreshToken);
      expect(refreshResult.success).toBe(false);
      expect(refreshResult.error).toBe('Invalid refresh token');
    });

    it('should logout from all devices', async () => {
      // Create multiple sessions
      await auth.login('test@example.com', 'password123', { userAgent: 'Device 1' });
      await auth.login('test@example.com', 'password123', { userAgent: 'Device 2' });
      
      await auth.logoutAll(userId);
      
      const refreshResult = await auth.refreshToken(refreshToken);
      expect(refreshResult.success).toBe(false);
    });
  });

  describe('token verification', () => {
    let accessToken: string;

    beforeAll(async () => {
      const result = await auth.register('token-test@example.com', 'password123');
      accessToken = result.accessToken!;
    });

    it('should verify valid access token', async () => {
      const user = await auth.verifyToken(accessToken);
      expect(user).toBeDefined();
      expect(user?.email).toBe('token-test@example.com');
    });

    it('should not verify invalid token', async () => {
      const user = await auth.verifyToken('invalid.token.here');
      expect(user).toBeNull();
    });
  });

  describe('verification tokens', () => {
    it('should generate and verify email verification token', async () => {
      const identifier = 'verify@example.com';
      const token = await auth.generateVerificationToken(identifier, 'email');
      expect(token).toBeDefined();
      expect(token.length).toBe(6);

      const isValid = await auth.verifyVerificationToken(identifier, token);
      expect(isValid).toBe(true);
    });

    it('should generate and verify password reset token', async () => {
      const identifier = 'reset@example.com';
      const token = await auth.generateVerificationToken(identifier, 'password_reset', {
        requestedAt: new Date()
      });
      expect(token).toBeDefined();

      const isValid = await auth.verifyVerificationToken(identifier, token);
      expect(isValid).toBe(true);
    });

    it('should not verify incorrect token', async () => {
      const identifier = 'verify2@example.com';
      await auth.generateVerificationToken(identifier);

      const isValid = await auth.verifyVerificationToken(identifier, '000000');
      expect(isValid).toBe(false);
    });

    it('should not verify token twice', async () => {
      const identifier = 'verify3@example.com';
      const token = await auth.generateVerificationToken(identifier);

      const firstVerify = await auth.verifyVerificationToken(identifier, token);
      expect(firstVerify).toBe(true);

      const secondVerify = await auth.verifyVerificationToken(identifier, token);
      expect(secondVerify).toBe(false);
    });
  });
});
