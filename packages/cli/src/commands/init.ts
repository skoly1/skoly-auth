import chalk from "chalk";
import { detectProject } from "../utils/detect";
import { getInitOptions } from "../utils/prompts";
import { writeConfig } from "../utils/config";
import { updateDependencies } from "../utils/deps";
import { Auth, PostgresAdapter } from "@skoly/auth-core";

interface InitOptions {
  secret?: string;
  yes?: boolean;
  database?: "postgres" | "mysql";
}

export async function init(options: InitOptions) {
  console.log(chalk.blue("Initializing Skoly Auth..."));

  try {
    // Detect project type
    const project = await detectProject();

    // Get configuration options
    const config = options.yes
      ? {
          secret: options.secret || crypto.randomUUID(),
          database: options.database || "postgres",
        }
      : await getInitOptions(options);

    // Initialize auth with Postgres adapter
    const auth = new Auth(new PostgresAdapter({
      connectionString: process.env.DATABASE_URL || ''
    }), {
      secret: config.secret,
      accessTokenExpiry: 15 * 60 * 1000, // 15 minutes in milliseconds
      refreshTokenExpiry: 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
    });

    // Generate config file
    await writeConfig(config);

    // Update package dependencies
    await updateDependencies(project);

    console.log(chalk.green("✓ Authentication initialized successfully"));
  } catch (error) {
    console.error(chalk.red("Error initializing auth:"), error);
    process.exit(1);
  }
}
