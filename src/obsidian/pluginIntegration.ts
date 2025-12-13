import { Plugin, Modal, App, Notice } from 'obsidian';
import crypto from 'crypto';
import { setMasterKey } from '../encryption/manager';
import { exportMasterKeyWrappedToFile, importMasterKeyWrappedFromFile } from '../encryption/exportImport';
import { getMasterKey } from '../encryption/manager';

type StoredSettings = {
  wrappedMaster?: string;
  wrapSalt?: string;
  wrapNonce?: string;
  wrapTag?: string;
};

class PasswordModal extends Modal {
  result: string | null = null;
  prompt: string;
  constructor(app: App, prompt: string) {
    super(app);
    this.prompt = prompt;
  }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl('h3', { text: this.prompt });
    const input = contentEl.createEl('input') as HTMLInputElement;
    input.type = 'password';
    input.style.width = '100%';
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.result = input.value;
        this.close();
      }
    });
    input.focus();
    const btn = contentEl.createEl('button', { text: 'OK' });
    btn.addEventListener('click', () => {
      this.result = input.value;
      this.close();
    });
  }
  onClose() {
    const { contentEl } = this;
    contentEl.empty();
  }
}

class FilePathModal extends Modal {
  result: string | null = null;
  prompt: string;
  constructor(app: App, prompt: string) {
    super(app);
    this.prompt = prompt;
  }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl('h3', { text: this.prompt });
    const input = contentEl.createEl('input') as HTMLInputElement;
    input.type = 'text';
    input.style.width = '100%';
    input.placeholder = '/path/to/file.bin';
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.result = input.value;
        this.close();
      }
    });
    input.focus();
    const btn = contentEl.createEl('button', { text: 'OK' });
    btn.addEventListener('click', () => {
      this.result = input.value;
      this.close();
    });
  }
  onClose() {
    const { contentEl } = this;
    contentEl.empty();
  }
}

// small helpers for prompting
function promptWithModal<T>(modal: Modal): Promise<T | null> {
  modal.open();
  return new Promise((resolve) => {
    const prev = (modal as any).onClose;
    (modal as any).onClose = () => {
      if (prev) prev();
      resolve((modal as any).result ?? null);
    };
  });
}

export default class FitEncryptionPlugin extends Plugin {
  settings: StoredSettings = {};
  masterKey?: Buffer; // in-memory unwrapped master key

  async onload() {
    await this.loadSettings();

    // Unlock/lock commands removed from this integration - encryption is handled automatically.

    this.addCommand({
      id: 'fit-migrate-fit-ids',
      name: 'FIT: Ensure stable IDs (add fit_id to Markdown files)',
      callback: async () => {
        try {
          const files = this.app.vault.getFiles();
          let checked = 0;
          let updated = 0;
          for (const f of files) {
            // Only operate on Markdown files to avoid touching binaries
            if (f.extension !== 'md') continue;
            checked++;
            const text = await this.app.vault.read(f);
            const fmMatch = text.match(/^---\n([\s\S]*?)\n---\n?/);
            let fm = '';
            let body = text;
            if (fmMatch) {
              fm = fmMatch[1];
              body = text.slice(fmMatch[0].length);
            }
            const idMatch = fm.match(/^fit_id:\s*(.+)$/m);
            if (idMatch && idMatch[1]) continue;
            const uuid = (globalThis as any).crypto?.randomUUID ? (globalThis as any).crypto.randomUUID() : require('crypto').randomUUID();
            const newFm = fm ? (fm + '\nfit_id: ' + uuid) : ('fit_id: ' + uuid);
            const newText = '---\n' + newFm + '\n---\n' + body;
            await this.app.vault.modify(f, newText);
            updated++;
          }
          new Notice(`FIT: checked ${checked} files, added fit_id to ${updated} files`);
        } catch (err) {
          console.error(err);
          new Notice('FIT: Migration failed');
        }
      },
    });

    this.addCommand({
      id: 'fit-export-master-key',
      name: 'FIT: Export master key (password-wrapped, safe for git)',
      callback: async () => {
        try {
          const mk = getMasterKey();
          if (!mk) {
            new Notice('No master key loaded in memory to export');
            return;
          }
          const password = await promptWithModal<string | null>(new PasswordModal(this.app, 'Enter password to wrap the master key'));
          if (!password) {
            new Notice('Export cancelled');
            return;
          }
          const filePath = await promptWithModal<string | null>(new FilePathModal(this.app, 'Enter file path to export wrapped master key to'));
          if (!filePath) {
            new Notice('Export cancelled');
            return;
          }
          await exportMasterKeyWrappedToFile(filePath, password);
          new Notice('Wrapped master key exported');
        } catch (err) {
          console.error('Wrapped export failed', err);
          new Notice('Wrapped export failed');
        }
      },
    });

    this.addCommand({
      id: 'fit-import-master-key',
      name: 'FIT: Import master key (password-wrapped)',
      callback: async () => {
        try {
          const filePath = await promptWithModal<string | null>(new FilePathModal(this.app, 'Enter file path to import wrapped master key from'));
          if (!filePath) {
            new Notice('Import cancelled');
            return;
          }
          const password = await promptWithModal<string | null>(new PasswordModal(this.app, 'Enter password to unwrap the master key'));
          if (!password) {
            new Notice('Import cancelled');
            return;
          }
          await importMasterKeyWrappedFromFile(filePath, password);
          this.masterKey = getMasterKey();
          new Notice('Wrapped master key imported and loaded into memory');
        } catch (err) {
          console.error('Wrapped import failed', err);
          new Notice('Wrapped import failed');
        }
      },
    });
  }

  async loadSettings() {
    this.settings = Object.assign({}, (await this.loadData()) as StoredSettings);
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  async deriveWrappingKey(password: string, salt: Buffer): Promise<Buffer> {
    // reuse encryption's Argon2 / scrypt fallback behaviour
    // we intentionally mirror same parameters as encrypt module
    try {
      const argon2 = await import('argon2');
      const raw = await (argon2 as any).hash(password, {
        type: (argon2 as any).argon2id,
        salt,
        raw: true,
        hashLength: 32,
        timeCost: 3,
        memoryCost: 1 << 16,
        parallelism: 1,
      });
      return Buffer.from(raw);
    } catch (e) {
      return crypto.scryptSync(password, salt, 32);
    }
  }

  async unlockFlow() {
    const modal = new PasswordModal(this.app, 'Enter password to unlock or create master key');
    modal.open();
    await new Promise((r) => (modal.onClose = r as any));
    const password = modal.result;
    if (!password) {
      new Notice('No password entered');
      return;
    }

    if (this.settings.wrappedMaster) {
      // unwrap existing master key
      try {
        const wrapSalt = Buffer.from(this.settings.wrapSalt!, 'base64');
        const wrapKey = await this.deriveWrappingKey(password, wrapSalt);
        const wrapNonce = Buffer.from(this.settings.wrapNonce!, 'base64');
        const wrapTag = Buffer.from(this.settings.wrapTag!, 'base64');
        const wrapped = Buffer.from(this.settings.wrappedMaster!, 'base64');
        const { getAeadAlgorithm } = await import('../encryption/alg');
        const algo = getAeadAlgorithm();
        const dec = crypto.createDecipheriv(algo, wrapKey, wrapNonce, { authTagLength: 16 } as any);
        (dec as any).setAuthTag(wrapTag);
        const master = Buffer.concat([dec.update(wrapped), dec.final()]);
        this.masterKey = master;
        setMasterKey(master);
        new Notice('FIT: master key unwrapped and loaded in memory');
      } catch (err) {
        console.error('Failed to unwrap master key', err);
        new Notice('Failed to unlock: wrong password or corrupted data');
      }
    } else {
      // create and persist a wrapped master key (one-time generation)
      const master = crypto.randomBytes(32);
      const wrapSalt = crypto.randomBytes(16);
      const wrapKey = await this.deriveWrappingKey(password, wrapSalt);
      const wrapNonce = crypto.randomBytes(12);
      const { getAeadAlgorithm } = await import('../encryption/alg');
      const algo = getAeadAlgorithm();
      const enc = crypto.createCipheriv(algo, wrapKey, wrapNonce, { authTagLength: 16 } as any);
      const wrapped = Buffer.concat([enc.update(master), enc.final()]);
      const wrapTag = (enc as any).getAuthTag();
      this.settings.wrappedMaster = wrapped.toString('base64');
      this.settings.wrapSalt = wrapSalt.toString('base64');
      this.settings.wrapNonce = wrapNonce.toString('base64');
      this.settings.wrapTag = wrapTag.toString('base64');
      await this.saveSettings();
      this.masterKey = master;
      setMasterKey(master);
      new Notice('FIT: new master key generated and stored (wrapped)');
    }
  }

}
