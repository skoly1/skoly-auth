#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { init } from "./commands/init";
import { add } from "./commands/add";
import { list } from "./commands/list";

const program = new Command()
  .name("create-skoly-auth")
  .description("Add authentication to your application")
  .version("0.0.1");

program
  .command("init")
  .description("Initialize authentication in your project")
  .option("-s, --secret <string>", "JWT secret key")
  .option("-y, --yes", "Skip prompts and use defaults")
  .option("-d, --database <type>", "Database type (postgres/mysql)")
  .action(init);

program
  .command("add")
  .description("Add an authentication component")
  .argument("[component]", "Component to add")
  .option("-y, --yes", "Skip prompts")
  .action(add);

program
  .command("list")
  .description("List all available components")
  .action(list);

program.parse();
