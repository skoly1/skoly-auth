import { readFile, writeFile } from 'fs/promises';
import { components } from './registry';

interface ProjectInfo {
  framework?: string;
  component?: string;
}

export async function updateDependencies(info: ProjectInfo) {
  const packageJson = JSON.parse(
    await readFile('./package.json', 'utf-8')
  );

  // Add core dependency
  packageJson.dependencies = {
    ...packageJson.dependencies,
    '@skoly/openauth': 'latest'
  };

  // Add component-specific deps
  if (info.component && components[info.component]) {
    const componentDeps = components[info.component].dependencies;
    packageJson.dependencies = {
      ...packageJson.dependencies,
      ...componentDeps
    };
  }

  await writeFile(
    './package.json',
    JSON.stringify(packageJson, null, 2)
  );
}