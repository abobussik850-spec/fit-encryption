Encryption module (modular, drop-in)

Purpose
- Implements Argon2id -> MASTER_KEY -> HKDF(file_id) -> FILE_KEY -> ChaCha20-Poly1305
- Designed to be autonomous and imported in a couple lines from the main project.

Quick usage
```ts
import encryption from './encryption';

const pkg = await encryption.encryptFile('user-password', 'file-id-123', Buffer.from('secret'), { aad: 'metadata' });
// store `pkg` alongside file in git

const plaintext = await encryption.decryptPackage('user-password', 'file-id-123', pkg, Buffer.from('metadata'));
```

Notes
- Module attempts to use `argon2` (dynamic import). If not installed it falls back to `crypto.scryptSync`.
- Requires Node that supports `crypto.hkdfSync` and `chacha20-poly1305` cipher (OpenSSL-backed).
- Output package uses base64 fields: `salt`, `nonce`, `ciphertext`, `tag`.
