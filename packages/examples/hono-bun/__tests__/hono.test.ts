import { describe, expect, it, beforeAll, afterAll } from 'bun:test';
import { createApp } from '../hono';

describe('Hono Auth Example', () => {
  const { app, db } = createApp();
  let accessToken: string;
  let refreshToken: string;

  // Helper function to make requests
  const request = (path: string, options: RequestInit = {}) => {
    return app.request(path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
  };

  beforeAll(async () => {
    await db.init();
  });

  afterAll(async () => {
    // Clean up database
    await db.close();
  });

  it('should register a new user', async () => {
    const res = await request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'password123'
      })
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.accessToken).toBeDefined();
    expect(data.refreshToken).toBeDefined();
    expect(data.session).toBeDefined();

    // Save tokens for later tests
    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
  });

  it('should fail registration with invalid data', async () => {
    const res = await request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com' // Missing password
      })
    });

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toBeDefined();
  });

  it('should login an existing user', async () => {
    const res = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'password123'
      })
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.accessToken).toBeDefined();
    expect(data.refreshToken).toBeDefined();
    expect(data.session).toBeDefined();
  });

  it('should fail login with wrong password', async () => {
    const res = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'wrongpassword'
      })
    });

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBeDefined();
  });

  it('should refresh tokens', async () => {
    const res = await request('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({
        refreshToken
      })
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.accessToken).toBeDefined();
    expect(data.refreshToken).toBeDefined();

    // Update tokens
    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
  });

  it('should access protected route with valid token', async () => {
    const res = await request('/protected', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.user).toBeDefined();
    expect(data.payload).toBeDefined();
  });

  it('should fail accessing protected route without token', async () => {
    const res = await request('/protected');
    expect(res.status).toBe(401);
  });

  it('should start email verification', async () => {
    const res = await request('/auth/verify/start', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com'
      })
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.token).toBeDefined();
    expect(data.message).toBe('Verification code sent');
  });

  it('should complete email verification', async () => {
    // First get a verification token
    const startRes = await request('/auth/verify/start', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com'
      })
    });
    const { token } = await startRes.json();

    // Then verify it
    const res = await request('/auth/verify/complete', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com',
        token
      })
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe('Email verified successfully');
  });

  it('should fail email verification with invalid token', async () => {
    const res = await request('/auth/verify/complete', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com',
        token: 'invalid-token'
      })
    });

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toBeDefined();
  });
});
