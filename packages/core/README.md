# @skoly/openauth

A flexible, platform-agnostic authentication library that works across Node.js, Bun, and Deno.

## Features

- Email/password authentication with secure hashing
- Access and refresh token support
- Multi-device session management
- PKCE support for enhanced security
- Verification token system for email/phone
- PostgreSQL support with native UUID
- Type-safe with full TypeScript support
- Framework agnostic
- Platform agnostic (Node.js, Bun, Deno)

## Installation

```bash
npm install @skoly/openauth pg
# or
yarn add @skoly/openauth pg
# or
pnpm add @skoly/openauth pg
# or
bun add @skoly/openauth pg
```

## Usage

### Basic Setup

```typescript
import { Auth, PostgresAdapter } from '@skoly/openauth';

// Initialize database adapter
const db = new PostgresAdapter({
  host: 'localhost',
  database: 'myapp',
  user: 'postgres',
  password: 'postgres'
});

// Initialize tables
await db.init();

// Create auth instance
const auth = new Auth(db, {
  secret: process.env.JWT_SECRET!, // Required for JWT signing
  accessTokenExpiry: 15 * 60, // 15 minutes in seconds
  refreshTokenExpiry: 7 * 24 * 60 * 60, // 7 days in seconds
  sessionExpiry: 30 * 24 * 60 * 60, // 30 days in seconds
  secureCookies: true // For production use
});
```

### User Registration

```typescript
const result = await auth.register(
  'user@example.com',
  'password123',
  {
    userAgent: req.headers['user-agent'],
    ipAddress: req.ip
  }
);

if (result.success) {
  // Registration successful
  console.log('Access Token:', result.accessToken);
  console.log('Refresh Token:', result.refreshToken);
  console.log('Session:', result.session);
} else {
  // Registration failed
  console.error('Error:', result.error);
}
```

### User Login

```typescript
const result = await auth.login(
  'user@example.com',
  'password123',
  {
    userAgent: req.headers['user-agent'],
    ipAddress: req.ip
  }
);

if (result.success) {
  // Login successful
  console.log('Access Token:', result.accessToken);
  console.log('Refresh Token:', result.refreshToken);
  console.log('Session:', result.session);
} else {
  // Login failed
  console.error('Error:', result.error);
}
```

### Token Refresh

```typescript
const result = await auth.refreshToken(refreshToken);

if (result.success) {
  // Token refresh successful
  console.log('New Access Token:', result.tokens.accessToken);
  console.log('New Refresh Token:', result.tokens.refreshToken);
} else {
  // Token refresh failed
  console.error('Error:', result.error);
}
```

### Session Management

```typescript
// Get user's active sessions
const sessions = await db.getUserSessions(userId);

// Logout from current device
await auth.logout(refreshToken);

// Logout from all devices
await auth.logoutAll(userId);
```

### Token Verification

```typescript
const user = await auth.verifyToken(token);

if (user) {
  // Token is valid
  console.log('User:', user.email);
} else {
  // Token is invalid or expired
  console.log('Invalid token');
}
```

### Email/Phone Verification

```typescript
// Generate verification token
const token = await auth.generateVerificationToken('user@example.com');

// Send token to user (implement your own sending logic)
await sendEmail(token);

// Later, verify the token
const isValid = await auth.verifyVerificationToken('user@example.com', token);

if (isValid) {
  // Token is valid
  console.log('Verification successful');
} else {
  // Token is invalid or expired
  console.log('Invalid verification token');
}
```

## API Reference

### `Auth`

Main authentication class that handles all auth operations.

```typescript
constructor(db: DatabaseAdapter, config: AuthConfig)
```

#### Configuration

```typescript
interface AuthConfig {
  secret: string;        // Secret key for JWT signing
  accessTokenExpiry?: number;  // Access token expiry (default: 15m)
  refreshTokenExpiry?: number; // Refresh token expiry (default: 7d)
  sessionExpiry?: number;      // Session expiry (default: 30d)
  secureCookies?: boolean;     // Use secure cookies (default: true)
  crypto?: CryptoAdapter;      // Custom crypto implementation
}
```

### `PostgresAdapter`

PostgreSQL implementation of the DatabaseAdapter interface.

```typescript
constructor(config: PoolConfig)
```

#### Database Schema

The adapter automatically creates the following tables with UUID support:

- `users`: Store user information (UUID primary key)
- `auth_credentials`: Store authentication credentials
- `auth_sessions`: Store active sessions with metadata
- `auth_refresh_tokens`: Store refresh tokens with revocation
- `auth_verification_tokens`: Store verification tokens

## Security Considerations

1. Always use HTTPS in production
2. Store JWT_SECRET securely
3. Use secure cookies in production
4. Implement rate limiting for auth endpoints
5. Regularly rotate refresh tokens
6. Monitor and audit sessions
7. Use appropriate token expiry times
8. Follow security best practices for your framework

## License

MIT
