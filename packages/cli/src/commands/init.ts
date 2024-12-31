import chalk from "chalk";
import { detectProject } from "../utils/detect";
import { getInitOptions } from "../utils/prompts";
import { writeConfig } from "../utils/config";
import { updateDependencies } from "../utils/deps";
import { Auth, PostgresAdapter } from "@skoly/auth-core";

interface InitOptions {
  secret: string;
  yes?: boolean;
  database: "postgres" | "mysql";
  dbConfig: {
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
  };
}

export async function init(options: InitOptions) {
  console.log(chalk.blue("Initializing Skoly Auth..."));

  try {
    // Detect project type
    const project = await detectProject();

    // Get configuration options
    const config = await getInitOptions(options);

    // Ensure required properties are set
    if (!config.secret) {
      config.secret = crypto.randomUUID();
    }
    if (!config.dbConfig) {
      config.dbConfig = {
        host: 'localhost',
        port: 5432,
        user: 'postgres',
        password: '',
        database: 'skoly_auth'
      };
    }

    // Initialize auth with Postgres adapter
    const auth = new Auth(new PostgresAdapter({
      host: config.dbConfig.host,
      port: config.dbConfig.port,
      user: config.dbConfig.user,
      password: config.dbConfig.password,
      database: config.dbConfig.database
    }), {
      secret: config.secret as string,
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
