export * from './types';
export * from './encrypt';
export * from './decrypt';

// Convenience default export: small wrapper for easy two-line integration
import * as E from './encrypt';
import * as D from './decrypt';

export default {
  encryptFile: E.encryptFile,
  deriveMasterKey: E.deriveMasterKey,
  deriveFileKey: E.deriveFileKey,
  decryptPackage: D.decryptPackage,
};

export * from './path';
