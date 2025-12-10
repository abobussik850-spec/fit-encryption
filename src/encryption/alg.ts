import crypto from 'crypto';

/**
 * Detect available AEAD algorithm to use. Prefer ChaCha20-Poly1305 when available,
 * otherwise fall back to AES-256-GCM which is widely supported.
 */
export function getAeadAlgorithm(): string {
  const ciphers = crypto.getCiphers();
  if (ciphers.includes('chacha20-poly1305')) return 'chacha20-poly1305';
  if (ciphers.includes('aes-256-gcm')) return 'aes-256-gcm';
  // Last resort - return aes-256-gcm and hope runtime supports it
  return 'aes-256-gcm';
}

export const AEAD_TAG_LENGTH = 16;
export const AEAD_NONCE_BYTES = 12;
