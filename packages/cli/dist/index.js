#!/usr/bin/env node

// ../../node_modules/.pnpm/tsup@8.3.5_postcss@8.4.49_typescript@5.7.2/node_modules/tsup/assets/esm_shims.js
import { fileURLToPath } from "url";
import path from "path";
var getFilename = () => fileURLToPath(import.meta.url);
var getDirname = () => path.dirname(getFilename());
var __dirname = /* @__PURE__ */ getDirname();

// src/index.ts
import { Command } from "commander";

// src/commands/init.ts
import chalk from "chalk";

// src/utils/detect.ts
import { readFile } from "fs/promises";

// src/utils/files.ts
import { mkdir, copyFile, access } from "fs/promises";
import { join } from "path";
async function exists(path2) {
  try {
    await access(path2);
    return true;
  } catch {
    return false;
  }
}
async function copyComponent(name) {
  const componentDir = join(process.cwd(), "components", "auth");
  await mkdir(componentDir, { recursive: true });
  const files = [`${name}.tsx`, `${name}.css`];
  for (const file of files) {
    try {
      await copyFile(
        join(__dirname, "../../templates/components", file),
        join(componentDir, file)
      );
    } catch (error) {
    }
  }
}

// src/utils/detect.ts
async function detectProject() {
  try {
    const packageJson = JSON.parse(
      await readFile("./package.json", "utf-8")
    );
    const framework = packageJson.dependencies?.next ? "next" : packageJson.dependencies?.express ? "express" : packageJson.dependencies?.hono ? "hono" : void 0;
    const hasTypeScript = await exists("./tsconfig.json");
    const database = packageJson.dependencies?.pg ? "postgres" : packageJson.dependencies?.mysql ? "mysql" : void 0;
    return {
      framework,
      database,
      hasTypeScript
    };
  } catch (error) {
    return { hasTypeScript: false };
  }
}

// src/utils/prompts.ts
import prompts from "prompts";

// src/utils/registry.ts
var components = {
  "password-login": {
    name: "Password Login",
    description: "Email and password based authentication",
    files: ["components/PasswordLogin.tsx", "lib/auth/password.ts"],
    dependencies: {
      "@skoly/auth-core": "latest"
    }
  },
  "oauth-buttons": {
    name: "OAuth Buttons",
    description: "Social login buttons",
    files: ["components/OAuthButtons.tsx", "lib/auth/oauth.ts"],
    dependencies: {
      "@skoly/auth-core": "latest"
    }
  }
};
async function getComponents() {
  return components;
}

// src/utils/prompts.ts
async function getInitOptions(options) {
  if (!options) options = {};
  const responses = await prompts([
    {
      type: "text",
      name: "secret",
      message: "Enter JWT secret (leave empty to generate)",
      initial: options.secret
    },
    {
      type: "select",
      name: "database",
      message: "Select database",
      choices: [
        { title: "PostgreSQL", value: "postgres" },
        { title: "MySQL", value: "mysql" }
      ],
      initial: options.database === "mysql" ? 1 : 0
    }
  ]);
  if (responses.database === "postgres") {
    const dbDetails = await prompts([
      {
        type: "text",
        name: "host",
        message: "Enter database host",
        initial: "localhost"
      },
      {
        type: "number",
        name: "port",
        message: "Enter database port",
        initial: 5432
      },
      {
        type: "text",
        name: "user",
        message: "Enter database user",
        initial: "postgres"
      },
      {
        type: "password",
        name: "password",
        message: "Enter database password"
      },
      {
        type: "text",
        name: "database",
        message: "Enter database name",
        validate: (value) => value ? true : "Database name is required"
      }
    ]);
    return {
      secret: responses.secret || crypto.randomUUID(),
      database: responses.database,
      dbConfig: dbDetails
    };
  }
  return {
    secret: responses.secret || crypto.randomUUID(),
    database: responses.database || "postgres",
    dbConfig: {
      host: "localhost",
      port: 5432,
      user: "postgres",
      password: "",
      database: "skoly_auth"
    }
  };
}
async function getComponent() {
  const components2 = await getComponents();
  const choices = Object.entries(components2).map(([value, { name }]) => ({
    title: name,
    value
  }));
  const result = await prompts({
    type: "select",
    name: "component",
    message: "Select component to add",
    choices
  });
  return result.component;
}

// src/utils/config.ts
import { writeFile } from "fs/promises";
async function writeConfig(config) {
  const content = `
import { Config } from '@skoly/auth-core';

export default {
  secret: '${config.secret}',
  database: {
    type: '${config.database}',
    host: '${config.dbConfig.host}',
    port: ${config.dbConfig.port},
    user: '${config.dbConfig.user}',
    password: '${config.dbConfig.password}',
    database: '${config.dbConfig.database}'
  }
} satisfies Config;
`;
  await writeFile("auth.config.ts", content);
}

// src/utils/deps.ts
import { readFile as readFile2, writeFile as writeFile2 } from "fs/promises";
async function updateDependencies(info) {
  const packageJson = JSON.parse(
    await readFile2("./package.json", "utf-8")
  );
  packageJson.dependencies = {
    ...packageJson.dependencies,
    "@skoly/auth-core": "latest"
  };
  if (info.component && components[info.component]) {
    const componentDeps = components[info.component].dependencies;
    packageJson.dependencies = {
      ...packageJson.dependencies,
      ...componentDeps
    };
  }
  await writeFile2(
    "./package.json",
    JSON.stringify(packageJson, null, 2)
  );
}

// src/commands/init.ts
import { Auth, PostgresAdapter } from "@skoly/auth-core";
async function init(options) {
  console.log(chalk.blue("Initializing Skoly Auth..."));
  try {
    const project = await detectProject();
    const config = await getInitOptions(options);
    if (!config.secret) {
      config.secret = crypto.randomUUID();
    }
    if (!config.dbConfig) {
      config.dbConfig = {
        host: "localhost",
        port: 5432,
        user: "postgres",
        password: "",
        database: "skoly_auth"
      };
    }
    const auth = new Auth(new PostgresAdapter({
      host: config.dbConfig.host,
      port: config.dbConfig.port,
      user: config.dbConfig.user,
      password: config.dbConfig.password,
      database: config.dbConfig.database
    }), {
      secret: config.secret,
      accessTokenExpiry: 15 * 60 * 1e3,
      // 15 minutes in milliseconds
      refreshTokenExpiry: 7 * 24 * 60 * 60 * 1e3
      // 7 days in milliseconds
    });
    await writeConfig(config);
    await updateDependencies(project);
    console.log(chalk.green("\u2713 Authentication initialized successfully"));
  } catch (error) {
    console.error(chalk.red("Error initializing auth:"), error);
    process.exit(1);
  }
}

// src/commands/add.ts
import chalk2 from "chalk";
async function add(component, options = {}) {
  try {
    const selectedComponent = component || await getComponent();
    await copyComponent(selectedComponent);
    await updateDependencies({ component: selectedComponent });
    console.log(chalk2.green(`\u2713 Added ${selectedComponent} component`));
  } catch (error) {
    console.error(chalk2.red("Error adding component:"), error);
    process.exit(1);
  }
}

// src/commands/list.ts
import chalk3 from "chalk";
async function list() {
  const components2 = await getComponents();
  console.log(chalk3.blue("\nAvailable components:\n"));
  for (const [name, component] of Object.entries(components2)) {
    console.log(`${chalk3.green(name)}`);
    console.log(`  ${component.description}`);
    console.log();
  }
}

// src/index.ts
var program = new Command().name("create-skoly-auth").description("Add authentication to your application").version("0.0.1");
program.command("init").description("Initialize authentication in your project").option("-s, --secret <string>", "JWT secret key").option("-y, --yes", "Skip prompts and use defaults").option("-d, --database <type>", "Database type (postgres/mysql)").action(init);
program.command("add").description("Add an authentication component").argument("[component]", "Component to add").option("-y, --yes", "Skip prompts").action(add);
program.command("list").description("List all available components").action(list);
program.parse();
