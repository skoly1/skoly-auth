import chalk from "chalk";
import { detectProject } from "../utils/detect";
import { getInitOptions } from "../utils/prompts";
import { writeConfig } from "../utils/config";
import { updateDependencies } from "../utils/deps";
import { Auth } from "@skoly/openauth";

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

    // Initialize auth
    const auth = new Auth({
      secret: config.secret,
    });

    await auth.init();

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
