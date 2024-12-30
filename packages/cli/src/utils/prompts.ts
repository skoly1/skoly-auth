import prompts from 'prompts';
import { getComponents } from './registry';

export async function getInitOptions(options: any) {
  return await prompts([
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