import { Command } from "commander";
import chalk from "chalk";
import { promises as fs } from "fs";
import path from "path";
import { execa } from "execa";
import prompts from "prompts";

const __dirname = path.resolve();

const ADAPTERS = {
  postgres: {
    package: "pg",
    description: "PostgreSQL database"
  },
  // mysql: {
  //   package: "mysql2",
  //   description: "MySQL database"
  // },
  // sqlite: {
  //   package: "better-sqlite3",
  //   description: "SQLite database"
  // }
} as const;

type AdapterKey = keyof typeof ADAPTERS;

export const download = new Command("download")
  .description("Install @skoly/auth-core with database adapter")
  .option("-d, --dir <directory>", "Target directory", ".")
  .action(async (options) => {
    try {
      const targetDir = path.resolve(options.dir);
      
      // Ensure target directory exists
      await fs.mkdir(targetDir, { recursive: true });

      // Prompt user to select adapter
      const { adapter } = await prompts({
        type: 'select',
        name: 'adapter',
        message: 'Select your database:',
        choices: Object.entries(ADAPTERS).map(([key, value]) => ({
          title: `${key} - ${value.description}`,
          value: key
        }))
      });

      if (!adapter) {
        console.log(chalk.yellow('Database selection cancelled'));
        return;
      }

      // Create basic configuration file
      const config = {
        adapter,
        databaseUrl: process.env.DATABASE_URL || ""
      };
      await fs.writeFile(
        path.join(targetDir, "skoly.config.json"),
        JSON.stringify(config, null, 2)
      );

      console.log(chalk.green(
        `Successfully set up authentication with ${adapter} adapter in ${targetDir}`
      ));
      console.log(chalk.yellow(
        "Don't forget to set DATABASE_URL environment variable"
      ));
      
      // Prompt to install dependencies
      const { install } = await prompts({
        type: 'confirm',
        name: 'install',
        message: 'Would you like to install required dependencies now?',
        initial: true
      });

      if (install) {
        console.log(chalk.blue('Installing dependencies...'));
        await execa('npm', [
          'install',
          '@skoly/auth-core',
          ADAPTERS[adapter as AdapterKey].package
        ], { stdio: 'inherit' });
        console.log(chalk.green('Dependencies installed successfully!'));
      } else {
        console.log(chalk.blue(
          "You can install required dependencies later by running:\n" +
          `npm install @skoly/auth-core ${ADAPTERS[adapter as AdapterKey].package}`
        ));
      }
    } catch (error) {
      if (error instanceof Error) {
        console.error(chalk.red("Error during installation:"), error.message);
      } else {
        console.error(chalk.red("Error during installation:"), error);
      }
      process.exit(1);
    }
  });
