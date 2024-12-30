import { readFile } from 'fs/promises';
import { exists } from './files';

interface ProjectInfo {
  framework?: 'next' | 'express' | 'hono';
  database?: 'postgres' | 'mysql';
  hasTypeScript: boolean;
}

export async function detectProject(): Promise<ProjectInfo> {
  try {
    // Read package.json
    const packageJson = JSON.parse(
      await readFile('./package.json', 'utf-8')
    );
    
    // Detect framework
    const framework = packageJson.dependencies?.next ? 'next'
      : packageJson.dependencies?.express ? 'express'
      : packageJson.dependencies?.hono ? 'hono'
      : undefined;

    // Detect TypeScript
    const hasTypeScript = await exists('./tsconfig.json');

    // Detect database
    const database = packageJson.dependencies?.pg ? 'postgres'
      : packageJson.dependencies?.mysql ? 'mysql'
      : undefined;

    return {
      framework,
      database,
      hasTypeScript
    };
  } catch (error) {
    return { hasTypeScript: false };
  }
}