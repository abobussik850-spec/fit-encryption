import { promises as fs } from 'fs';
import path from 'path';
import { getMasterKey, setMasterKey } from './manager';
import crypto from 'crypto';
import { getAeadAlgorithm } from './alg';

function ensureMasterKey(): Buffer {
  const mk = getMasterKey();
  if (!mk) throw new Error('no master key in memory');
  if (!Buffer.isBuffer(mk)) throw new Error('invalid master key');
  if (mk.length !== 32) throw new Error('unexpected master key length');
  return mk;
}

export async function exportMasterKeyToFile(filePath: string): Promise<void> {
  const mk = ensureMasterKey();
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, mk, { mode: 0o600 });
}

export async function importMasterKeyFromFile(filePath: string): Promise<void> {
  const buf = await fs.readFile(filePath);
  if (!Buffer.isBuffer(buf) || buf.length !== 32) throw new Error('invalid key file');
  setMasterKey(buf);
}

async function deriveWrappingKey(password: string, salt: Buffer): Promise<Buffer> {
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
  } catch {
    return crypto.scryptSync(password, salt, 32);
  }
}

type WrappedFile = {
  version: number;
  wrapSalt: string;
  wrapNonce: string;
  wrapTag: string;
  wrapped: string;
};

export async function exportMasterKeyWrappedToFile(filePath: string, password: string): Promise<void> {
  const mk = ensureMasterKey();
  const wrapSalt = crypto.randomBytes(16);
  const wrapKey = await deriveWrappingKey(password, wrapSalt);
  const wrapNonce = crypto.randomBytes(12);
  const algo = getAeadAlgorithm();
  const cipher = crypto.createCipheriv(algo, wrapKey, wrapNonce, { authTagLength: 16 } as any);
  const wrapped = Buffer.concat([cipher.update(mk), cipher.final()]);
  const wrapTag = (cipher as any).getAuthTag();
  const out: WrappedFile = {
    version: 1,
    wrapSalt: wrapSalt.toString('base64'),
    wrapNonce: wrapNonce.toString('base64'),
    wrapTag: wrapTag.toString('base64'),
    wrapped: wrapped.toString('base64'),
  };
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(out), { mode: 0o600 });
}

export async function importMasterKeyWrappedFromFile(filePath: string, password: string): Promise<void> {
  const raw = await fs.readFile(filePath, { encoding: 'utf8' });
  let obj: WrappedFile;
  try {
    obj = JSON.parse(raw) as WrappedFile;
  } catch (err) {
    throw new Error('invalid wrapped key file');
  }
  if (!obj || !obj.wrapSalt || !obj.wrapNonce || !obj.wrapTag || !obj.wrapped) throw new Error('invalid wrapped key file');
  const wrapSalt = Buffer.from(obj.wrapSalt, 'base64');
  const wrapKey = await deriveWrappingKey(password, wrapSalt);
  const wrapNonce = Buffer.from(obj.wrapNonce, 'base64');
  const wrapTag = Buffer.from(obj.wrapTag, 'base64');
  const wrapped = Buffer.from(obj.wrapped, 'base64');
  const algo = getAeadAlgorithm();
  const dec = crypto.createDecipheriv(algo, wrapKey, wrapNonce, { authTagLength: 16 } as any);
  (dec as any).setAuthTag(wrapTag);
  const master = Buffer.concat([dec.update(wrapped), dec.final()]);
  if (master.length !== 32) throw new Error('invalid unwrapped master key');
  setMasterKey(master);
}
