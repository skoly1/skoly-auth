import { writeFile } from 'fs/promises';

interface AuthConfig {
  secret: string;
  database?: {
    type: string;
    url?: string;
  };
}

export async function writeConfig(config: AuthConfig) {
  const content = `
import { Config } from '@skoly/auth-core';

export default {
  secret: '${config.secret}',
  ${config.database ? `
  database: {
    type: '${config.database.type}',
    ${config.database.url ? `url: '${config.database.url}'` : ''}
  },` : ''}
} satisfies Config;
`;

  await writeFile('auth.config.ts', content);
}
