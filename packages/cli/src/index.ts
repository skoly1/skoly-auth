#!/usr/bin/env node
import { Command } from 'commander';
import { generateAuthFiles } from './generate';
import { selectDatabase } from './prompts';

const program = new Command();

program
  .name('@skoly/auth-cli')
  .description('CLI for setting up authentication in Node.js projects')
  .version('0.1.0');

program
  .command('init')
  .description('Initialize authentication setup')
  .action(async () => {
    console.log('Starting authentication setup...');
    try {
      console.log('Prompting for database selection...');
      const dbType = await selectDatabase();
      console.log(`Selected database: ${dbType}`);
      console.log('Generating auth files...');
      await generateAuthFiles(dbType);
      console.log('✓ Authentication setup complete! Files generated in ./auth directory');
    } catch (error) {
      console.error('Error setting up authentication:', error);
      process.exit(1);
    }
  });

program.parse(process.argv);
