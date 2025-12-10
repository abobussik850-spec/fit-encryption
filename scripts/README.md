Local build & install helper

Usage:

- Build production bundle:
```
npm run build
```

- Install built plugin into Obsidian plugins folder (use env var or pass path):
```
VAULT_PLUGIN_DIR=~/.config/obsidian/YourVault/plugins npm run dev:install
# or
node scripts/install-plugin.js /full/path/to/vault/plugins
```

- Create zip for upload to Obsidian community plugins page (requires `zip` available):
```
npm run package:zip
```

Notes:
- `scripts/install-plugin.js` copies `main.js`, `manifest.json` and `styles.css` if present.
- `VAULT_PLUGIN_DIR` should point to the `plugins` folder for your vault (open Obsidian → Settings → Community plugins → Open plugin folder to find it).
- For development loop, run `npm run dev` in one terminal and `npm run dev:install` after each rebuild (or create a small watcher to copy automatically).
