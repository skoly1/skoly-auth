# @skoly/auth-cli

A CLI tool to set up authentication in your Node.js project.

## Installation

```bash
# Install globally
pnpm install -g @skoly/auth-cli

# Or use directly with npx
npx @skoly/auth-cli init
```

## Features

- 🚀 Interactive setup wizard
- 🔒 Secure authentication system
- 🗃️ Database adapter selection (PostgreSQL, MongoDB, MySQL, SQLite)
- 📂 Generates files directly in your project
- ⚙️ Configurable authentication settings
- 🛠️ Fully customizable generated code

## Usage

1. Initialize authentication setup:
```bash
skoly-auth init
```

2. The CLI will guide you through:
   - Database selection
   - Database connection details
   - Authentication configuration
   - File generation

3. The following files will be created in your project:
```
auth/
  ├── auth.ts         # Core authentication logic
  ├── config.ts       # Authentication configuration
  ├── types.ts        # TypeScript interfaces and types
  └── db/
      └── [database].ts # Database-specific configuration
```

4. Install required database driver:
```bash
# For PostgreSQL
pnpm install pg

# For MySQL
pnpm install mysql2

# For SQLite
pnpm install better-sqlite3
```

## Configuration

The generated `auth/config.ts` file contains your authentication configuration:

```typescript
export const authConfig = {
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  sessionDuration: '24h',
  passwordRequirements: {
    minLength: 8,
    requireNumbers: true,
    requireSpecialChars: true
  }
};
```

Set environment variables in your project:
```bash
export DATABASE_URL=your_database_url
export JWT_SECRET=your_jwt_secret
```

## Development

To build the CLI locally:

```bash
pnpm install
pnpm build
```

For development with watch mode:

```bash
pnpm dev
```

## License

MIT - See [LICENSE](../../LICENSE) for more information.
