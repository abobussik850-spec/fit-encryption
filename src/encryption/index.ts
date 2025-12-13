export * from './types';
export * from './encrypt';
export * from './decrypt';
export * from './exportImport';

// Convenience default export: small wrapper for easy two-line integration
import * as E from './encrypt';
import * as D from './decrypt';
import * as EI from './exportImport';

export default {
  encryptFile: E.encryptFile,
  deriveMasterKey: E.deriveMasterKey,
  deriveFileKey: E.deriveFileKey,
  decryptPackage: D.decryptPackage,
  exportMasterKeyToFile: EI.exportMasterKeyToFile,
  importMasterKeyFromFile: EI.importMasterKeyFromFile,
};

export * from './path';
