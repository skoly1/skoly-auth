# @skoly/auth-cli

A CLI tool to download and set up @skoly/auth-core authentication in your project.

## Installation

```bash
# Using npm
npm install -g @skoly/auth-cli

# Using npx (recommended)
npx @skoly/auth-cli download <adapter>
```

## Features

- 🚀 Quick setup of authentication system
- 🔒 Secure by default
- 🛠️ Database adapter selection (postgres, mysql, sqlite)
- 📦 Copies core source code to your project
- ⚙️ Creates configuration file

## Usage

1. Download authentication setup:
```bash
npx @skoly/auth-cli download <adapter>
```

Available adapters:
- postgres

2. The CLI will:
   - Copy core authentication source files
   - Create skoly.config.json
   - Provide installation instructions

3. Install required dependencies:
```bash
npm install pg # or mysql2/better-sqlite3
```

4. Set environment variable:
```bash
export DATABASE_URL=your_database_url
```

## Configuration

The CLI creates a `skoly.config.json` file with your authentication configuration:

```json
{
  "adapter": "postgres",
  "databaseUrl": ""
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
