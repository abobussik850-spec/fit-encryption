import crypto from 'crypto';
import type { EncryptedPackage } from './types';

export async function deriveMasterKeyFromSalt(password: string, salt: Buffer): Promise<Buffer> {
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
  } catch (err) {
    // fallback to scrypt
    return crypto.scryptSync(password, salt, 32);
  }
}

function deriveFileKey(masterKey: Buffer, fileId: string): Buffer {
  const info = Buffer.from(fileId, 'utf8');
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), info, 32));
}

export function decryptWithFileKey(fileKey: Buffer, nonce: Buffer, ciphertext: Buffer, tag: Buffer, aad?: Buffer): Buffer {
  const decipher = crypto.createDecipheriv('chacha20-poly1305', fileKey, nonce, { authTagLength: 16 });
  if (aad) decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext;
}

export async function decryptPackage(password: string, fileId: string, pkg: EncryptedPackage, aad?: Buffer): Promise<Buffer> {
  const salt = Buffer.from(pkg.salt, 'base64');
  const nonce = Buffer.from(pkg.nonce, 'base64');
  const ciphertext = Buffer.from(pkg.ciphertext, 'base64');
  const tag = Buffer.from(pkg.tag, 'base64');
  const masterKey = await deriveMasterKeyFromSalt(password, salt);
  const fileKey = deriveFileKey(masterKey, fileId);
  return decryptWithFileKey(fileKey, nonce, ciphertext, tag, aad);
}
