# Skoly Auth

A modern, type-safe authentication library for Node.js applications.

## Features

- 🔒 Secure authentication with JWT tokens
- 📦 Modular monorepo structure using PNPM workspaces
- 🚀 Built with TypeScript for type safety
- 🔌 Extensible database adapters (currently supports PostgreSQL)
- 🧪 Comprehensive test suite with Bruno API collections
- ⚡ Example implementation using Hono and Bun

## Project Structure

```
packages/
  ├── core/         # Core authentication library
  └── examples/     # Example implementations
      └── hono-bun/ # Example using Hono and Bun
```

## Getting Started

1. Install dependencies:
```bash
pnpm install
```

2. Build all packages:
```bash
pnpm build
```

3. Run the example server:
```bash
cd packages/examples/hono-bun
bun run dev
```

## Packages

### Core (@skoly/auth-core)
The core authentication library that provides:
- JWT-based authentication
- Session management
- User management
- Database adapters
- Type-safe API

```typescript
import { createAuth } from '@skoly/auth-core';
import { PostgresAdapter } from '@skoly/auth-core/adapters';

const auth = createAuth({
  adapter: new PostgresAdapter({
    connectionString: process.env.DATABASE_URL
  })
});
```

### Examples
The `examples/hono-bun` directory contains a complete example implementation using:
- Hono.js for the web framework
- Bun as the runtime
- PostgreSQL for the database
- Bruno API collections for testing

## API Documentation

### Authentication Endpoints

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login and get access token
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

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For security concerns, please email [saiteja.g1801@gmail.com](mailto:saiteja.g1801@gmail.com).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
