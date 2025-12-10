import crypto from 'crypto';
import type { EncryptedPackage, EncryptOptions } from './types';

async function tryArgon2(password: string, salt: Buffer, length = 32): Promise<Buffer> {
  try {
    // dynamic import so module is optional
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const argon2 = await import('argon2');
    const raw = await (argon2 as any).hash(password, {
      type: (argon2 as any).argon2id,
      salt,
      raw: true,
      hashLength: length,
      timeCost: 3,
      memoryCost: 1 << 16,
      parallelism: 1,
    });
    return Buffer.from(raw);
  } catch (err) {
    // Fallback to scrypt if argon2 not available — weaker but allows usage without installing extra deps
    const N = 16384; // not used by scryptSync; placeholder
    return crypto.scryptSync(password, salt, length);
  }
}

export async function deriveMasterKey(password: string, saltIn?: Buffer): Promise<{ masterKey: Buffer; salt: Buffer }> {
  const salt = saltIn ?? crypto.randomBytes(16);
  const masterKey = await tryArgon2(password, salt, 32);
  return { masterKey, salt };
}

export function deriveFileKey(masterKey: Buffer, fileId: string): Buffer {
  // Use HKDF-SHA256 with fileId as info to derive a separate file key
  const info = Buffer.from(fileId, 'utf8');
  // hkdfSync(node) signature: (digest, ikm, salt, info, keylen)
  // no salt passed here (we already used salt in master key derivation)
  return crypto.hkdfSync('sha256', masterKey, undefined, info, 32);
}

export function encryptWithFileKey(fileKey: Buffer, plaintext: Buffer, aad?: Buffer): { nonce: Buffer; ciphertext: Buffer; tag: Buffer } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('chacha20-poly1305', fileKey, nonce, { authTagLength: 16 });
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce, ciphertext, tag };
}

export async function encryptFile(password: string, fileId: string, plaintext: Buffer, opts?: EncryptOptions): Promise<EncryptedPackage> {
  const { masterKey, salt } = await deriveMasterKey(password);
  const fileKey = deriveFileKey(masterKey, fileId);
  const aadBuf = opts?.aad ? Buffer.isBuffer(opts.aad) ? opts.aad : Buffer.from(String(opts.aad), 'utf8') : undefined;
  const { nonce, ciphertext, tag } = encryptWithFileKey(fileKey, plaintext, aadBuf);
  return {
    version: 1,
    salt: salt.toString('base64'),
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
  };
}
