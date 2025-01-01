#!/usr/bin/env node
import{Command as d}from"commander";import o from"fs-extra";import i from"path";async function a(e){console.log("Starting file generation...");let t=i.join(process.cwd(),"auth");console.log(`Creating auth directory at: ${t}`),await o.ensureDir(t),console.log("Auth directory created");let r=i.join(t,"db");console.log(`Creating db directory at: ${r}`),await o.ensureDir(r),console.log("db directory created"),await Promise.all([o.writeFile(i.join(t,"auth.ts"),c()),o.writeFile(i.join(t,"db",`${e}.ts`),l(e)),o.writeFile(i.join(t,"types.ts"),u()),o.writeFile(i.join(t,"config.ts"),g())])}function c(){return`// Core authentication logic
export * from './types';
export * from './config';
`}function l(e){return`// ${e} specific database configuration
export const dbConfig = {
  // Add your ${e} configuration here
};
`}function u(){return`// TypeScript interfaces and types
export interface User {
  id: string;
  email: string;
  password: string;
}

export interface Session {
  userId: string;
  token: string;
  expiresAt: Date;
}
`}function g(){return`// Authentication configuration
export const authConfig = {
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  sessionDuration: '24h',
  passwordRequirements: {
    minLength: 8,
    requireNumbers: true,
    requireSpecialChars: true
  }
};
`}import p from"prompts";async function s(){return(await p({type:"select",name:"database",message:"Select your database:",choices:[{title:"PostgreSQL",value:"postgres"},{title:"MongoDB",value:"mongodb"},{title:"MySQL",value:"mysql"},{title:"SQLite",value:"sqlite"}],initial:0})).database}var n=new d;n.name("@skoly/auth-cli").description("CLI for setting up authentication in Node.js projects").version("0.1.0");n.command("init").description("Initialize authentication setup").action(async()=>{console.log("Starting authentication setup...");try{console.log("Prompting for database selection...");let e=await s();console.log(`Selected database: ${e}`),console.log("Generating auth files..."),await a(e),console.log("\u2713 Authentication setup complete! Files generated in ./auth directory")}catch(e){console.error("Error setting up authentication:",e),process.exit(1)}});n.parse(process.argv);
//# sourceMappingURL=index.js.map