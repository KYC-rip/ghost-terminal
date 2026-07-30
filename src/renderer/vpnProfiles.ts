import { Unzip, UnzipInflate } from 'fflate';

export type VpnProfileKind = 'wireguard' | 'openvpn';

export interface VpnProfile {
  id: string;
  name: string;
  sourcePath: string;
  kind: VpnProfileKind;
  configText: string;
}

const MAX_ARCHIVE_BYTES = 2 * 1024 * 1024;
const MAX_PROFILE_BYTES = 16 * 1024;
const MAX_PROFILES = 128;
const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Safe profile preview. Connection code must continue using the untouched
 * configText; this projection exists solely to keep screenshots and shoulder
 * surfing from disclosing tunnel credentials. */
export function redactVpnProfileSecrets(text: string): string {
  return text
    .replace(/^(\s*(?:PrivateKey|PresharedKey)\s*=\s*).+$/gim, '$1[hidden]')
    .replace(
      /(<(?:key|pkcs12|auth-user-pass)>)[\s\S]*?(<\/(?:key|pkcs12|auth-user-pass)>)/gi,
      '$1\n[hidden]\n$2',
    );
}

function kindFor(name: string): VpnProfileKind | null {
  const lower = name.toLowerCase();
  if (lower.endsWith('.conf')) return 'wireguard';
  if (lower.endsWith('.ovpn')) return 'openvpn';
  return null;
}

function safeArchivePath(name: string): boolean {
  if (!name || name.includes('\0') || name.includes('\\') || name.startsWith('/')) return false;
  return !name.split('/').some(part => part === '..');
}

function profileName(path: string): string {
  const file = path.split('/').pop() || path;
  return file.replace(/\.(conf|ovpn)$/i, '');
}

function decodeProfile(sourcePath: string, kind: VpnProfileKind, bytes: Uint8Array, index: number): VpnProfile {
  if (bytes.byteLength > MAX_PROFILE_BYTES) {
    throw new Error(`${sourcePath} exceeds the 16 KiB profile limit.`);
  }
  let configText: string;
  try { configText = utf8.decode(bytes); }
  catch { throw new Error(`${sourcePath} is not valid UTF-8 text.`); }
  if (configText.includes('\0')) throw new Error(`${sourcePath} contains binary data.`);
  if (kind === 'wireguard' && (!/\[Interface\]/i.test(configText) || !/\[Peer\]/i.test(configText))) {
    throw new Error(`${sourcePath} is not a WireGuard client profile.`);
  }
  if (kind === 'openvpn' && !/^\s*(client|remote)\b/im.test(configText)) {
    throw new Error(`${sourcePath} is not an OpenVPN client profile.`);
  }
  return {
    id: `${index}:${sourcePath}`,
    name: profileName(sourcePath),
    sourcePath,
    kind,
    configText,
  };
}

function readZipProfiles(bytes: Uint8Array): Promise<VpnProfile[]> {
  return new Promise((resolve, reject) => {
    const profiles: VpnProfile[] = [];
    let pending = 0;
    let inputFinished = false;
    let settled = false;

    const fail = (reason: unknown) => {
      if (settled) return;
      settled = true;
      reject(reason instanceof Error ? reason : new Error(String(reason)));
    };
    const finish = () => {
      if (settled || !inputFinished || pending !== 0) return;
      settled = true;
      if (!profiles.length) reject(new Error('The archive contains no .conf or .ovpn profiles.'));
      else resolve(profiles);
    };

    const unzip = new Unzip(file => {
      if (settled) return;
      const kind = kindFor(file.name);
      if (!kind) return;
      if (!safeArchivePath(file.name)) {
        fail(new Error(`Unsafe profile path in archive: ${file.name}`));
        return;
      }
      if (profiles.length + pending >= MAX_PROFILES) {
        fail(new Error(`Profile bundle exceeds the ${MAX_PROFILES}-profile limit.`));
        return;
      }
      if (typeof file.originalSize === 'number' && file.originalSize > MAX_PROFILE_BYTES) {
        fail(new Error(`${file.name} exceeds the 16 KiB profile limit.`));
        return;
      }

      pending += 1;
      const chunks: Uint8Array[] = [];
      let total = 0;
      file.ondata = (error, chunk, final) => {
        if (settled) return;
        if (error) { fail(error); return; }
        total += chunk.byteLength;
        if (total > MAX_PROFILE_BYTES) {
          file.terminate();
          fail(new Error(`${file.name} exceeds the 16 KiB profile limit.`));
          return;
        }
        chunks.push(chunk);
        if (!final) return;
        const body = new Uint8Array(total);
        let offset = 0;
        for (const part of chunks) { body.set(part, offset); offset += part.byteLength; }
        try { profiles.push(decodeProfile(file.name, kind, body, profiles.length)); }
        catch (e) { fail(e); return; }
        pending -= 1;
        finish();
      };
      try { file.start(); }
      catch (e) { fail(e); }
    });
    unzip.register(UnzipInflate);
    try {
      unzip.push(bytes, true);
      inputFinished = true;
      finish();
    } catch (e) { fail(e); }
  });
}

export async function readVpnProfileBytes(fileName: string, bytes: Uint8Array): Promise<VpnProfile[]> {
  const kind = kindFor(fileName);
  if (kind) return [decodeProfile(fileName, kind, bytes, 0)];
  if (!fileName.toLowerCase().endsWith('.zip')) {
    throw new Error('Choose a WireGuard .conf, OpenVPN .ovpn, or ZIP profile bundle.');
  }
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) {
    throw new Error('Profile bundle exceeds the 2 MiB compressed archive limit.');
  }
  return readZipProfiles(bytes);
}

export async function readVpnProfileFile(file: File): Promise<VpnProfile[]> {
  return readVpnProfileBytes(file.name, new Uint8Array(await file.arrayBuffer()));
}
