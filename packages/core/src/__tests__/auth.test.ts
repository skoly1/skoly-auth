import { describe, it, expect, beforeAll, afterAll } from 'vitest';
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
      tokenExpiry: 3600 // 1 hour
    });
  });

  afterAll(async () => {
    await db.close();
  });

  describe('registration', () => {
    it('should register a new user', async () => {
      const result = await auth.register('test@example.com', 'password123');
      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
    });

    it('should not register duplicate email', async () => {
      const result = await auth.register('test@example.com', 'password123');
      expect(result.success).toBe(false);
      expect(result.error).toBe('User already exists');
    });
  });

  describe('login', () => {
    it('should login with correct credentials', async () => {
      const result = await auth.login('test@example.com', 'password123');
      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
    });

    it('should not login with incorrect password', async () => {
      const result = await auth.login('test@example.com', 'wrongpassword');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });

    it('should not login non-existent user', async () => {
      const result = await auth.login('nonexistent@example.com', 'password123');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });
  });

  describe('token verification', () => {
    let userToken: string;

    beforeAll(async () => {
      const result = await auth.register('token-test@example.com', 'password123');
      userToken = result.token!;
    });

    it('should verify valid token', async () => {
      const user = await auth.verifyToken(userToken);
      expect(user).toBeDefined();
      expect(user?.email).toBe('token-test@example.com');
    });

    it('should not verify invalid token', async () => {
      const user = await auth.verifyToken('invalid.token.here');
      expect(user).toBeNull();
    });
  });

  describe('verification tokens', () => {
    it('should generate and verify token', async () => {
      const identifier = 'verify@example.com';
      const token = await auth.generateVerificationToken(identifier);
      expect(token).toBeDefined();
      expect(token.length).toBe(6);

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
