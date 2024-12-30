import chalk from 'chalk';
import { getComponents } from '../utils/registry';

export async function list() {
  const components = await getComponents();
  
  console.log(chalk.blue('\nAvailable components:\n'));
  
  for (const [name, component] of Object.entries(components)) {
    console.log(`${chalk.green(name)}`);
    console.log(`  ${component.description}`);
    console.log();
  }
}
