#!/usr/bin/env node
import { Command } from 'commander'
import chalk from 'chalk'
import { Auth } from '@skoly/openauth'

const program = new Command()

program
  .name('create-skoly-auth')
  .description('Add authentication to your application')
  .version('0.0.1')

program
  .command('init')
  .description('Initialize authentication in your project')
  .option('-s, --secret <string>', 'JWT secret key')
  .action(async (options) => {
    console.log(chalk.blue('Initializing Skoly Auth...'))
    
    try {
      const auth = new Auth({
        secret: options.secret || crypto.randomUUID()
      })

      await auth.init()
      
      console.log(chalk.green('✓ Authentication initialized successfully'))
    } catch (error) {
      console.error(chalk.red('Error initializing auth:'), error)
      process.exit(1)
    }
  })

program.parse()