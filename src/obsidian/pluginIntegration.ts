import { Plugin, Modal, App, Notice, TFile } from 'obsidian';
import crypto from 'crypto';
import encryption, { deriveFileKey, encryptWithFileKey, decryptWithFileKey } from '../encryption';
import { setMasterKey, clearMasterKey } from '../encryption/manager';

type StoredSettings = {
  wrappedMaster?: string; // base64 ciphertext
  wrapSalt?: string; // base64
  wrapNonce?: string; // base64
  wrapTag?: string; // base64
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

export default class FitEncryptionPlugin extends Plugin {
  settings: StoredSettings = {};
  masterKey?: Buffer; // in-memory unwrapped master key

  async onload() {
    await this.loadSettings();

    this.addCommand({
      id: 'fit-unlock-encryption',
      name: 'FIT: Unlock encryption (enter password or create master key)',
      callback: async () => this.unlockFlow(),
    });

    this.addCommand({
      id: 'fit-lock-encryption',
      name: 'FIT: Lock encryption (forget master key in memory)',
      callback: async () => {
        this.masterKey = undefined;
        clearMasterKey();
        new Notice('FIT: master key cleared from memory');
      },
    });

    this.addCommand({
      id: 'fit-encrypt-active-file',
      name: 'FIT: Encrypt active file',
      callback: async () => this.encryptActiveFile(),
    });

    this.addCommand({
      id: 'fit-decrypt-active-file',
      name: 'FIT: Decrypt active file',
      callback: async () => this.decryptActiveFile(),
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
        const dec = crypto.createDecipheriv('chacha20-poly1305', wrapKey, wrapNonce, { authTagLength: 16 });
        dec.setAuthTag(wrapTag);
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
      const enc = crypto.createCipheriv('chacha20-poly1305', wrapKey, wrapNonce, { authTagLength: 16 });
      const wrapped = Buffer.concat([enc.update(master), enc.final()]);
      const wrapTag = enc.getAuthTag();
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

  async encryptActiveFile() {
    if (!this.masterKey) {
      new Notice('Unlock FIT first (command: FIT: Unlock encryption)');
      return;
    }
    const file = this.app.workspace.getActiveFile();
    if (!file) {
      new Notice('No active file');
      return;
    }
    try {
      const content = await this.app.vault.read(file);
      const fileId = file.path; // NOTE: prefer a stable ID (UUID) in production
      const fileKey = deriveFileKey(this.masterKey, fileId);
      const aad = Buffer.from(file.path, 'utf8');
      const { nonce, ciphertext, tag } = encryptWithFileKey(fileKey, Buffer.from(content, 'utf8'), aad);
      const pkg = {
        version: 1,
        salt: '', // salt is unused because we use persisted masterKey
        nonce: nonce.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        tag: tag.toString('base64'),
      };
      await this.app.vault.modify(file, JSON.stringify(pkg, null, 2));
      new Notice('File encrypted (in-place)');
    } catch (err) {
      console.error(err);
      new Notice('Encryption failed');
    }
  }

  async decryptActiveFile() {
    if (!this.masterKey) {
      new Notice('Unlock FIT first (command: FIT: Unlock encryption)');
      return;
    }
    const file = this.app.workspace.getActiveFile();
    if (!file) {
      new Notice('No active file');
      return;
    }
    try {
      const content = await this.app.vault.read(file);
      const pkg = JSON.parse(content) as any;
      if (!pkg || !pkg.nonce) {
        new Notice('File does not look like FIT-encrypted package');
        return;
      }
      const fileId = file.path; // same id used before
      const fileKey = deriveFileKey(this.masterKey, fileId);
      const aad = Buffer.from(file.path, 'utf8');
      const plaintext = decryptWithFileKey(
        fileKey,
        Buffer.from(pkg.nonce, 'base64'),
        Buffer.from(pkg.ciphertext, 'base64'),
        Buffer.from(pkg.tag, 'base64'),
        aad,
      );
      await this.app.vault.modify(file, plaintext.toString('utf8'));
      new Notice('File decrypted');
    } catch (err) {
      console.error(err);
      new Notice('Decryption failed (wrong key, fileId or corrupted data)');
    }
  }
}
