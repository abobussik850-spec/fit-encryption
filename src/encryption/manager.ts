let masterKeyBuffer: Buffer | undefined = undefined;

export function setMasterKey(buf: Buffer) {
  masterKeyBuffer = Buffer.from(buf);
}

export function clearMasterKey() {
  masterKeyBuffer = undefined;
}

export function getMasterKey(): Buffer | undefined {
  return masterKeyBuffer;
}

export function hasMasterKey(): boolean {
  return !!masterKeyBuffer;
}
