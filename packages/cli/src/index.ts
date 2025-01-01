#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { download } from "./commands/download.js";

const program = new Command()
  .name("create-skoly-auth")
  .description("Download framework-specific authentication code")
  .version("0.1.0");

program.addCommand(download);

program.parse(process.argv);
