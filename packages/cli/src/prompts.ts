import prompts from 'prompts';

export async function selectDatabase() {
  const response = await prompts({
    type: 'select',
    name: 'database',
    message: 'Select your database:',
    choices: [
      { title: 'PostgreSQL', value: 'postgres' },
      { title: 'MongoDB', value: 'mongodb' },
      { title: 'MySQL', value: 'mysql' },
      { title: 'SQLite', value: 'sqlite' }
    ],
    initial: 0
  });

  return response.database;
}
