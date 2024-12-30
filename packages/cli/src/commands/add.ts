import chalk from "chalk";
import { getComponent } from "../utils/prompts";
import { copyComponent } from "../utils/files";
import { updateDependencies } from "../utils/deps";

export async function add(component?: string, options: { yes?: boolean } = {}) {
  try {
    // Get component selection if not specified
    const selectedComponent = component || (await getComponent());

    // Copy component files
    await copyComponent(selectedComponent);

    // Update dependencies
    await updateDependencies({ component: selectedComponent });

    console.log(chalk.green(`✓ Added ${selectedComponent} component`));
  } catch (error) {
    console.error(chalk.red("Error adding component:"), error);
    process.exit(1);
  }
}
