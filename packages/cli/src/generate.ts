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
  
  // Copy files from @skoly/auth-core package
  await Promise.all([
    fs.copyFile(
      require.resolve('@skoly/auth-core/src/index.ts'),
      path.join(authDir, 'auth.ts')
    ),
    fs.copyFile(
      require.resolve('@skoly/auth-core/src/adapters/postgres.ts'),
      path.join(authDir, 'db', `${dbType}.ts`)
    ),
    fs.copyFile(
      require.resolve('@skoly/auth-core/src/types.ts'),
      path.join(authDir, 'types.ts')
    ),
    fs.writeFile(
      path.join(authDir, 'config.ts'),
      generateConfigFileContent()
    )
  ]);
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
