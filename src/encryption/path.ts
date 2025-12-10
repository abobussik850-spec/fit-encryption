import { encryptWithFileKey } from './encrypt';
import { decryptWithFileKey } from './decrypt';

function toBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(s: string): Buffer {
  // restore padding
  const pad = 4 - (s.length % 4);
  const padded = s + (pad < 4 ? '='.repeat(pad) : '');
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64, 'base64');
}

export function encryptPathSegments(fileKey: Buffer, path: string): string {
  const parts = path.split('/');
  const encParts = parts.map(segment => {
    const { nonce, ciphertext, tag } = encryptWithFileKey(fileKey, Buffer.from(segment, 'utf8'));
    return `${toBase64Url(nonce)}.${toBase64Url(ciphertext)}.${toBase64Url(tag)}`;
  });
  return encParts.join('/');
}

export function decryptPathSegments(fileKey: Buffer, encryptedPath: string): string {
  const parts = encryptedPath.split('/');
  const decParts = parts.map(seg => {
    const parts2 = seg.split('.');
    if (parts2.length !== 3) throw new Error('NotAnEncryptedSegment');
    const nonce = fromBase64Url(parts2[0]);
    const ciphertext = fromBase64Url(parts2[1]);
    const tag = fromBase64Url(parts2[2]);
    const plain = decryptWithFileKey(fileKey, nonce, ciphertext, tag);
    return plain.toString('utf8');
  });
  return decParts.join('/');
}
