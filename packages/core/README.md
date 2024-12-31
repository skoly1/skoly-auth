# @skoly/auth-core

A flexible, platform-agnostic authentication library that works across Node.js, Bun, and Deno.

## Features

- 🔒 Email/password authentication with secure hashing
- 🎟️ Access and refresh token support
- 📱 Multi-device session management
- 🔐 PKCE support for enhanced security
- ✉️ Verification token system for email/phone
- 🗄️ PostgreSQL support with native UUID
- 📝 Type-safe with full TypeScript support
- 🔌 Framework agnostic
- 🌐 Platform agnostic (Node.js, Bun, Deno)
- 🧪 Comprehensive test suite

## Installation

```bash
npm install @skoly/auth-core pg
# or
yarn add @skoly/auth-core pg
# or
pnpm add @skoly/auth-core pg
# or
bun add @skoly/auth-core pg
```

## Quick Start

```typescript
import { Auth, PostgresAdapter } from '@skoly/auth-core';

// Initialize database adapter
const db = new PostgresAdapter({
  connectionString: process.env.DATABASE_URL
});

// Initialize auth
const auth = new Auth(db, {
  secret: process.env.JWT_SECRET!,
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  secureCookies: process.env.NODE_ENV === 'production'
});

// Register a user
const result = await auth.register('user@example.com', 'password123');

// Login
const { accessToken, refreshToken } = await auth.login('user@example.com', 'password123');
```

## Framework Examples

### Hono

```typescript
import { Hono } from 'hono';
import { Auth, PostgresAdapter } from '@skoly/auth-core';

const app = new Hono();
const auth = new Auth(new PostgresAdapter({ /* config */ }), { /* options */ });

app.post('/auth/register', async (c) => {
  const { email, password } = await c.req.json();
  const result = await auth.register(email, password);
  return c.json(result);
});

app.post('/auth/login', async (c) => {
  const { email, password } = await c.req.json();
  const result = await auth.login(email, password);
  return c.json(result);
});

app.get('/protected', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const user = await auth.verifyToken(token);
  if (!user) return c.json({ error: 'Unauthorized' }, 401);
  return c.json({ user });
});
```

### Express

```typescript
import express from 'express';
import { Auth, PostgresAdapter } from '@skoly/auth-core';

const app = express();
const auth = new Auth(new PostgresAdapter({ /* config */ }), { /* options */ });

app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const result = await auth.register(email, password);
  res.json(result);
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await auth.login(email, password);
  res.json(result);
});

app.get('/protected', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = await auth.verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ user });
});
```

## Database Schema

The PostgreSQL adapter creates the following tables:

### users
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### auth_credentials
```sql
CREATE TABLE auth_credentials (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### auth_sessions
```sql
CREATE TABLE auth_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  user_agent TEXT,
  ip_address VARCHAR(45),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

### auth_refresh_tokens
```sql
CREATE TABLE auth_refresh_tokens (
  token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID REFERENCES auth_sessions(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked_at TIMESTAMP WITH TIME ZONE
);
```

### auth_verification_tokens
```sql
CREATE TABLE auth_verification_tokens (
  token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

## API Reference

### Auth Class

```typescript
class Auth {
  constructor(db: DatabaseAdapter, config: AuthConfig);
  
  // User Management
  register(email: string, password: string, options?: SessionOptions): Promise<AuthResult>;
  login(email: string, password: string, options?: SessionOptions): Promise<AuthResult>;
  logout(refreshToken: string): Promise<void>;
  logoutAll(userId: string): Promise<void>;
  
  // Token Management
  verifyToken(token: string): Promise<User | null>;
  refreshToken(token: string): Promise<TokenResult>;
  revokeToken(token: string): Promise<void>;
  revokeAllTokens(userId: string): Promise<void>;
  
  // Verification
  generateVerificationToken(email: string): Promise<string>;
  verifyVerificationToken(email: string, token: string): Promise<boolean>;
}
```

### Configuration

```typescript
interface AuthConfig {
  secret: string;              // JWT signing secret
  accessTokenExpiry?: string;  // e.g., '15m', '1h' (default: '15m')
  refreshTokenExpiry?: string; // e.g., '7d', '30d' (default: '7d')
  secureCookies?: boolean;     // Use secure cookies (default: true)
  crypto?: CryptoAdapter;      // Custom crypto implementation
}

interface SessionOptions {
  userAgent?: string;          // Client user agent
  ipAddress?: string;          // Client IP address
  metadata?: Record<string, any>; // Additional session metadata
}
```

## Testing

The library includes a comprehensive test suite. To run the tests:

```bash
# Run tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run tests with coverage
pnpm test:coverage
```

### Writing Tests

```typescript
import { Auth, PostgresAdapter } from '@skoly/auth-core';
import { describe, it, expect } from 'vitest';

describe('Auth', () => {
  const auth = new Auth(new PostgresAdapter({ /* test config */ }));

  it('should register a new user', async () => {
    const result = await auth.register('test@example.com', 'password123');
    expect(result.success).toBe(true);
    expect(result.accessToken).toBeDefined();
  });
});
```

## Security Best Practices

1. **Environment Variables**
   - Store sensitive data (JWT secret, database credentials) in environment variables
   - Use different secrets for development and production

2. **HTTPS**
   - Always use HTTPS in production
   - Enable secure cookies in production

3. **Password Security**
   - Passwords are hashed using bcrypt
   - Implement password complexity requirements
   - Add rate limiting for auth endpoints

4. **Session Management**
   - Short-lived access tokens (15 minutes recommended)
   - Refresh tokens with reasonable expiry (7 days recommended)
   - Ability to revoke sessions and tokens

5. **Database Security**
   - Use connection pooling
   - Implement proper database backup
   - Use prepared statements (built-in)

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details on:
- Development setup
- Code style
- Pull request process
- Testing requirements

## License

MIT - See [LICENSE](../../LICENSE) for details.
