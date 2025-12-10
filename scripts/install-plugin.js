#!/usr/bin/env node
// Simple installer: copies main.js, manifest.json and optional files into target Obsidian plugins folder
import fs from 'fs/promises';
import path from 'path';

const repoRoot = path.resolve(new URL(import.meta.url).pathname, '..', '..');

function usage() {
  console.log('Usage: VAULT_PLUGIN_DIR=/path/to/vault/plugins node scripts/install-plugin.js [targetDir]');
  console.log('Or: node scripts/install-plugin.js /path/to/vault/plugins');
}

async function main() {
  const arg = process.argv[2];
  const envDir = process.env.VAULT_PLUGIN_DIR;
  const target = arg || envDir;
  if (!target) {
    usage();
    process.exit(1);
  }

  const dest = path.resolve(target, 'fit');
  await fs.mkdir(dest, { recursive: true });

  const files = ['main.js', 'manifest.json', 'styles.css'];
  for (const f of files) {
    const src = path.resolve(repoRoot, f);
    try {
      await fs.copyFile(src, path.resolve(dest, f));
      console.log(`Copied ${f} -> ${path.resolve(dest, f)}`);
    } catch (err) {
      // ignore missing optional files
      if (err.code === 'ENOENT') {
        console.log(`Skipping missing ${f}`);
      } else {
        console.error(`Failed copying ${f}:`, err);
      }
    }
  }

  console.log('Install complete. Restart Obsidian or reload plugins.');
}

main().catch((err) => { console.error(err); process.exitCode = 2; });
