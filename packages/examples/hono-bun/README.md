# Hono + Bun Example

This example demonstrates how to use `@skoly/openauth` with [Hono](https://hono.dev/) and [Bun](https://bun.sh/).

## Features

- 🚀 Full authentication system
- 🔒 JWT-based authentication
- 📦 Session management
- 🔑 Token refresh flow
- ✉️ Email verification
- 🧪 API tests using Bruno

## Prerequisites

- [Bun](https://bun.sh/) installed
- PostgreSQL database
- [Bruno](https://www.usebruno.com/) for API testing (optional)

## Getting Started

1. Install dependencies:
```bash
bun install
```

2. Set up environment variables:
```bash
# .env
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
JWT_SECRET=your-secret-key
```

3. Run the development server:
```bash
bun run dev
```

## API Endpoints

### Authentication

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login user
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout current session
- `POST /auth/logout-all` - Logout all sessions

### User Management

- `GET /users/:id` - Get user by ID
- `GET /users/email/:email` - Get user by email
- `PUT /users/:id` - Update user
- `DELETE /users/:id` - Delete user
- `GET /users/:id/sessions` - Get user sessions

### Token Management

- `POST /token/verify` - Verify token
- `POST /token/generate-verification` - Generate verification token
- `POST /token/verify-verification` - Verify verification token
- `POST /token/revoke` - Revoke refresh token
- `POST /token/revoke-all` - Revoke all refresh tokens for a user

## Testing

This example includes a comprehensive set of API tests using Bruno. The tests are located in the `bruno/skoly-auth` directory.

To run the tests:

1. Open Bruno
2. Import the collection from `bruno/skoly-auth`
3. Run the collection

## Implementation Details

### Server Setup

```typescript
import { Hono } from 'hono';
import { Auth, PostgresAdapter } from '@skoly/openauth';

const app = new Hono();
const db = new PostgresAdapter({
  connectionString: process.env.DATABASE_URL
});

const auth = new Auth(db, {
  secret: process.env.JWT_SECRET!,
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d'
});
```

### Authentication Middleware

```typescript
async function authMiddleware(c: Context, next: Next) {
  const token = c.req.header('Authorization')?.split(' ')[1];
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const user = await auth.verifyToken(token);
  if (!user) {
    return c.json({ error: 'Invalid token' }, 401);
  }

  c.set('user', user);
  await next();
}
```

### Protected Routes

```typescript
app.get('/protected', authMiddleware, (c) => {
  const user = c.get('user');
  return c.json({ message: 'Protected route', user });
});
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection URL | Yes |
| `JWT_SECRET` | Secret key for JWT signing | Yes |
| `PORT` | Server port (default: 3000) | No |

## Error Handling

The example includes comprehensive error handling:

```typescript
app.onError((err, c) => {
  console.error(err);
  return c.json({
    error: err.message || 'Internal Server Error'
  }, err.status || 500);
});
```

## Contributing

See the main [CONTRIBUTING.md](../../../CONTRIBUTING.md) for details.

## License

MIT - See the main [LICENSE](../../../LICENSE) for details.
