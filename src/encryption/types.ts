export type EncryptedPackage = {
  version?: number; // increment when format changes
  salt: string; // base64
  nonce: string; // base64
  ciphertext: string; // base64
  tag: string; // base64
};

export type EncryptOptions = {
  aad?: Buffer | string;
};
