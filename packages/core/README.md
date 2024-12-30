# @skoly/openauth

A flexible, database-agnostic authentication library for Node.js applications.

## Features

- Email/password authentication
- JWT token generation and verification
- Verification token system for email/phone verification
- PostgreSQL support out of the box
- Type-safe with full TypeScript support
- Framework agnostic

## Installation

```bash
npm install @skoly/openauth pg
# or
yarn add @skoly/openauth pg
# or
pnpm add @skoly/openauth pg
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
  tokenExpiry: 24 * 60 * 60, // 24 hours in seconds
  secureCookies: true // For production use
});
```

### User Registration

```typescript
const result = await auth.register('user@example.com', 'password123');

if (result.success) {
  // Registration successful
  console.log('JWT Token:', result.token);
} else {
  // Registration failed
  console.error('Error:', result.error);
}
```

### User Login

```typescript
const result = await auth.login('user@example.com', 'password123');

if (result.success) {
  // Login successful
  console.log('JWT Token:', result.token);
} else {
  // Login failed
  console.error('Error:', result.error);
}
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
  tokenExpiry?: number;  // Token expiry in seconds (default: 24h)
  secureCookies?: boolean; // Use secure cookies (default: true)
}
```

### `PostgresAdapter`

PostgreSQL implementation of the DatabaseAdapter interface.

```typescript
constructor(config: PoolConfig)
```

#### Database Schema

The adapter automatically creates the following tables:

- `users`: Store user information
- `auth_credentials`: Store authentication credentials
- `auth_sessions`: Store active sessions
- `auth_verification_tokens`: Store verification tokens

## Security Considerations

1. Always use HTTPS in production
2. Store JWT_SECRET securely
3. Use secure cookies in production
4. Implement rate limiting for auth endpoints
5. Follow security best practices for your framework

## License

MIT
