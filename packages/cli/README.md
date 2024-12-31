# create-skoly-auth

A CLI tool to quickly set up authentication in your Node.js applications using @skoly/auth-core.

## Installation

```bash
# Using npm
npm create skoly-auth@latest

# Using yarn
yarn create skoly-auth

# Using pnpm
pnpm create skoly-auth
```

## Features

- 🚀 Quick setup of authentication system
- 🔒 Secure by default
- 🎯 Interactive CLI interface
- 📦 Automatic dependency installation
- 🛠️ Framework-specific configurations

## Usage

1. Create a new authentication setup:
```bash
npm create skoly-auth@latest
```

2. Follow the interactive prompts to:
   - Choose your framework (Hono, Express, etc.)
   - Configure database settings
   - Set up authentication options

3. The CLI will:
   - Create necessary configuration files
   - Install required dependencies
   - Set up database adapters
   - Generate type-safe authentication code

## Commands

### `create-skoly-auth init`
Initialize a new authentication setup in your project.

```bash
create-skoly-auth init
```

### `create-skoly-auth add`
Add authentication to an existing route or component.

```bash
create-skoly-auth add
```

### `create-skoly-auth list`
List all available authentication components and configurations.

```bash
create-skoly-auth list
```

## Configuration

The CLI will create a `skoly.config.json` file in your project root with your authentication configuration:

```json
{
  "framework": "hono",
  "database": "postgres",
  "features": [
    "jwt",
    "sessions",
    "passwordReset"
  ]
}
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
