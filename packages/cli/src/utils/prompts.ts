import prompts from 'prompts';
import { getComponents } from './registry';

interface InitOptions {
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

export async function getInitOptions(options: any): Promise<InitOptions> {
  if (!options) options = {};
  const responses = await prompts([
    {
      type: 'text',
      name: 'secret',
      message: 'Enter JWT secret (leave empty to generate)',
      initial: options.secret
    },
    {
      type: 'select',
      name: 'database',
      message: 'Select database',
      choices: [
        { title: 'PostgreSQL', value: 'postgres' },
        { title: 'MySQL', value: 'mysql' }
      ],
      initial: options.database === 'mysql' ? 1 : 0
    }
  ]);

  if (responses.database === 'postgres') {
    const dbDetails = await prompts([
      {
        type: 'text',
        name: 'host',
        message: 'Enter database host',
        initial: 'localhost'
      },
      {
        type: 'number',
        name: 'port',
        message: 'Enter database port',
        initial: 5432
      },
      {
        type: 'text',
        name: 'user',
        message: 'Enter database user',
        initial: 'postgres'
      },
      {
        type: 'password',
        name: 'password',
        message: 'Enter database password'
      },
      {
        type: 'text',
        name: 'database',
        message: 'Enter database name',
        validate: value => value ? true : 'Database name is required'
      }
    ]);

    return {
      secret: responses.secret || crypto.randomUUID(),
      database: responses.database,
      dbConfig: dbDetails
    };
  }

  return {
    secret: responses.secret || crypto.randomUUID(),
    database: responses.database || 'postgres',
    dbConfig: {
      host: 'localhost',
      port: 5432,
      user: 'postgres',
      password: '',
      database: 'skoly_auth'
    }
  };
}

export async function getComponent() {
  const components = await getComponents();
  const choices = Object.entries(components).map(([value, { name }]) => ({
    title: name,
    value
  }));

  const result = await prompts({
    type: 'select',
    name: 'component',
    message: 'Select component to add',
    choices
  });

  return result.component;
}
