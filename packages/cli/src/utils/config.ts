import { writeFile } from 'fs/promises';

interface AuthConfig {
  secret: string;
  database: "postgres" | "mysql";
  dbConfig: {
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
  };
}

export async function writeConfig(config: AuthConfig) {
  const content = `
import { Config } from '@skoly/auth-core';

export default {
  secret: '${config.secret}',
  database: {
    type: '${config.database}',
    host: '${config.dbConfig.host}',
    port: ${config.dbConfig.port},
    user: '${config.dbConfig.user}',
    password: '${config.dbConfig.password}',
    database: '${config.dbConfig.database}'
  }
} satisfies Config;
`;

  await writeFile('auth.config.ts', content);
}
