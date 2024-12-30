import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Express } from 'express';
import supertest from 'supertest';
import { createApp } from '../express';
import type { Auth } from 'src';
import type { PostgresAdapter } from 'src/adapters/postgres';

describe('Express Integration', () => {
  let app: Express;
  let db: PostgresAdapter;
  let auth: Auth;
  let testUserToken: string;

  beforeAll(async () => {
    const result = createApp();
    app = result.app;
    db = result.db;
    auth = result.auth;
    await db.init();
  });

  afterAll(async () => {
    await db.close();
  });

  describe('Registration', () => {
    it('should register a new user', async () => {
      const res = await supertest(app)
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
      testUserToken = res.body.token;
    });

    it('should not register with missing data', async () => {
      const res = await supertest(app)
        .post('/auth/register')
        .send({
          email: 'test@example.com'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Email and password required');
    });

    it('should not register duplicate email', async () => {
      const res = await supertest(app)
        .post('/auth/register')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('User already exists');
    });
  });

  describe('Login', () => {
    it('should login with correct credentials', async () => {
      const res = await supertest(app)
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
    });

    it('should not login with incorrect password', async () => {
      const res = await supertest(app)
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword'
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid credentials');
    });

    it('should not login with non-existent user', async () => {
      const res = await supertest(app)
        .post('/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password123'
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid credentials');
    });
  });

  describe('Protected Routes', () => {
    it('should access protected route with valid token', async () => {
      const res = await supertest(app)
        .get('/protected')
        .set('Authorization', `Bearer ${testUserToken}`);

      expect(res.status).toBe(200);
      expect(res.body.user).toBeDefined();
      expect(res.body.user.email).toBe('test@example.com');
    });

    it('should not access protected route without token', async () => {
      const res = await supertest(app)
        .get('/protected');

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('No token provided');
    });

    it('should not access protected route with invalid token', async () => {
      const res = await supertest(app)
        .get('/protected')
        .set('Authorization', 'Bearer invalid.token.here');

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid token');
    });
  });

  describe('Verification', () => {
    let verificationToken: string;

    it('should generate verification token', async () => {
      const res = await supertest(app)
        .post('/auth/verify/start')
        .send({
          email: 'verify@example.com'
        });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeDefined();
      verificationToken = res.body.token;
    });

    it('should verify valid token', async () => {
      const res = await supertest(app)
        .post('/auth/verify/complete')
        .send({
          email: 'verify@example.com',
          token: verificationToken
        });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Email verified successfully');
    });

    it('should not verify invalid token', async () => {
      const res = await supertest(app)
        .post('/auth/verify/complete')
        .send({
          email: 'verify@example.com',
          token: '000000'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid or expired token');
    });

    it('should not verify token twice', async () => {
      const res = await supertest(app)
        .post('/auth/verify/complete')
        .send({
          email: 'verify@example.com',
          token: verificationToken
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid or expired token');
    });
  });
});
