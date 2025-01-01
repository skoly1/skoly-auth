import fs from 'fs-extra';
import path from 'path';
import { DatabaseType } from './types';

export async function generateAuthFiles(dbType: DatabaseType) {
  console.log('Starting file generation...');
  const authDir = path.join(process.cwd(), 'auth');
  console.log(`Creating auth directory at: ${authDir}`);
  
  // Create auth directory
  await fs.ensureDir(authDir);
  console.log('Auth directory created');
  
  // Create subdirectories
  const dbDir = path.join(authDir, 'db');
  console.log(`Creating db directory at: ${dbDir}`);
  await fs.ensureDir(dbDir);
  console.log('db directory created');
  
  // Generate files
  await Promise.all([
    fs.writeFile(
      path.join(authDir, 'auth.ts'),
      generateAuthFileContent()
    ),
    fs.writeFile(
      path.join(authDir, 'db', `${dbType}.ts`),
      generateDbFileContent(dbType)
    ),
    fs.writeFile(
      path.join(authDir, 'types.ts'),
      generateTypesFileContent()
    ),
    fs.writeFile(
      path.join(authDir, 'config.ts'),
      generateConfigFileContent()
    )
  ]);
}

function generateAuthFileContent(): string {
  return `// Core authentication logic
export * from './types';
export * from './config';
`;
}

function generateDbFileContent(dbType: DatabaseType): string {
  return `// ${dbType} specific database configuration
export const dbConfig = {
  // Add your ${dbType} configuration here
};
`;
}

function generateTypesFileContent(): string {
  return `// TypeScript interfaces and types
export interface User {
  id: string;
  email: string;
  password: string;
}

export interface Session {
  userId: string;
  token: string;
  expiresAt: Date;
}
`;
}

function generateConfigFileContent(): string {
  return `// Authentication configuration
export const authConfig = {
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  sessionDuration: '24h',
  passwordRequirements: {
    minLength: 8,
    requireNumbers: true,
    requireSpecialChars: true
  }
};
`;
}
