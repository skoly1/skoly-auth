import { mkdir, copyFile, access } from 'fs/promises';
import { join } from 'path';

export async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function copyComponent(name: string) {
  const componentDir = join(process.cwd(), 'components', 'auth');
  await mkdir(componentDir, { recursive: true });
  
  // Copy component files
  const files = [`${name}.tsx`, `${name}.css`];
  
  for (const file of files) {
    try {
      await copyFile(
        join(__dirname, '../../templates/components', file),
        join(componentDir, file)
      );
    } catch (error) {
      // Skip if file doesn't exist in template
    }
  }
}
