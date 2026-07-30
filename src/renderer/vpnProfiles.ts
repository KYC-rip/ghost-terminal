import { Unzip, UnzipInflate } from 'fflate';

export type VpnProfileKind = 'wireguard' | 'openvpn';

export interface VpnProfile {
  id: string;
  name: string;
  sourcePath: string;
  kind: VpnProfileKind;
  configText: string;
  /**
   * Rail group label for this profile’s import pack (usually the ZIP basename).
   * Profiles from the same bundle share one section; missing → inferred fallback.
   */
  bundle?: string;
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

/** Human-readable group label from an import source file name. */
export function bundleLabelFromSource(fileName: string): string {
  const base = fileName.split(/[/\\]/).pop() || fileName;
  return base
    .replace(/\.zip$/i, '')
    .replace(/\.(conf|ovpn)$/i, '')
    .trim() || base;
}

function decodeProfile(
  sourcePath: string,
  kind: VpnProfileKind,
  bytes: Uint8Array,
  index: number,
  bundle?: string,
): VpnProfile {
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
    ...(bundle ? { bundle } : {}),
  };
}

export type ImportReject = { name: string; reason: string };

/** Soft-fail result so one bad entry does not discard a whole OpenVPN/WG bundle. */
export type ZipReadResult = {
  profiles: VpnProfile[];
  skipped: ImportReject[];
};

function readZipProfiles(bytes: Uint8Array, bundle?: string): Promise<ZipReadResult> {
  return new Promise((resolve, reject) => {
    const profiles: VpnProfile[] = [];
    const skipped: ImportReject[] = [];
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
      if (!profiles.length && !skipped.length) {
        reject(new Error('The archive contains no .conf or .ovpn profiles.'));
      } else if (!profiles.length) {
        reject(new Error(
          skipped[0]
            ? `No valid profiles in archive (${skipped[0].name}: ${skipped[0].reason})`
            : 'The archive contains no valid .conf or .ovpn profiles.',
        ));
      } else {
        resolve({ profiles, skipped });
      }
    };

    const unzip = new Unzip(file => {
      if (settled) return;
      const kind = kindFor(file.name);
      if (!kind) return;
      if (!safeArchivePath(file.name)) {
        // Path traversal is a hard fail — do not partially trust the archive.
        fail(new Error(`Unsafe profile path in archive: ${file.name}`));
        return;
      }
      if (profiles.length + pending >= MAX_PROFILES) {
        fail(new Error(`Profile bundle exceeds the ${MAX_PROFILES}-profile limit.`));
        return;
      }
      if (typeof file.originalSize === 'number' && file.originalSize > MAX_PROFILE_BYTES) {
        skipped.push({ name: file.name, reason: `exceeds the ${MAX_PROFILE_BYTES / 1024} KiB profile limit` });
        return;
      }

      pending += 1;
      const chunks: Uint8Array[] = [];
      let total = 0;
      file.ondata = (error, chunk, final) => {
        if (settled) return;
        if (error) {
          skipped.push({ name: file.name, reason: String(error) });
          pending -= 1;
          finish();
          return;
        }
        total += chunk.byteLength;
        if (total > MAX_PROFILE_BYTES) {
          file.terminate();
          skipped.push({ name: file.name, reason: `exceeds the ${MAX_PROFILE_BYTES / 1024} KiB profile limit` });
          pending -= 1;
          finish();
          return;
        }
        chunks.push(chunk);
        if (!final) return;
        const body = new Uint8Array(total);
        let offset = 0;
        for (const part of chunks) { body.set(part, offset); offset += part.byteLength; }
        try {
          profiles.push(decodeProfile(file.name, kind, body, profiles.length, bundle));
        } catch (e) {
          skipped.push({ name: file.name, reason: String((e as Error)?.message || e) });
        }
        pending -= 1;
        finish();
      };
      try { file.start(); }
      catch (e) {
        skipped.push({ name: file.name, reason: String((e as Error)?.message || e) });
        pending -= 1;
        finish();
      }
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
  const bundle = bundleLabelFromSource(fileName);
  if (kind) return [decodeProfile(fileName, kind, bytes, 0, bundle)];
  if (!fileName.toLowerCase().endsWith('.zip')) {
    throw new Error('Choose a WireGuard .conf, OpenVPN .ovpn, or ZIP profile bundle.');
  }
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) {
    throw new Error('Profile bundle exceeds the 2 MiB compressed archive limit.');
  }
  const { profiles } = await readZipProfiles(bytes, bundle);
  return profiles;
}

/** Like readVpnProfileBytes, but preserves per-entry skip reasons from ZIP bundles. */
export async function readVpnProfileBytesDetailed(
  fileName: string,
  bytes: Uint8Array,
): Promise<ZipReadResult> {
  const kind = kindFor(fileName);
  const bundle = bundleLabelFromSource(fileName);
  if (kind) return { profiles: [decodeProfile(fileName, kind, bytes, 0, bundle)], skipped: [] };
  if (!fileName.toLowerCase().endsWith('.zip')) {
    throw new Error('Choose a WireGuard .conf, OpenVPN .ovpn, or ZIP profile bundle.');
  }
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) {
    throw new Error('Profile bundle exceeds the 2 MiB compressed archive limit.');
  }
  return readZipProfiles(bytes, bundle);
}

export async function readVpnProfileFile(file: File): Promise<VpnProfile[]> {
  return readVpnProfileBytes(file.name, new Uint8Array(await file.arrayBuffer()));
}

/** Result of staging one or more files for the dedicated Import screen. */
export type ImportStage = {
  additions: VpnProfile[];
  duplicates: string[];
  rejected: ImportReject[];
  sources: string[];
};

/**
 * Parse files in memory and classify each profile as add / duplicate / reject.
 * Never overwrites — names already present in `existingNames` become duplicates.
 */
export async function stageVpnImport(
  files: File[],
  existingNames: Iterable<string>,
): Promise<ImportStage> {
  const existing = new Set([...existingNames].map(n => n.toLowerCase()));
  const seen = new Set<string>();
  const additions: VpnProfile[] = [];
  const duplicates: string[] = [];
  const rejected: ImportReject[] = [];
  const sources: string[] = [];

  for (const file of files) {
    sources.push(file.name);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const { profiles: loaded, skipped } = await readVpnProfileBytesDetailed(file.name, bytes);
      for (const skip of skipped) {
        rejected.push({ name: `${file.name} → ${skip.name}`, reason: skip.reason });
      }
      for (const profile of loaded) {
        const key = profile.name.toLowerCase();
        if (existing.has(key) || seen.has(key)) {
          duplicates.push(profile.name);
          continue;
        }
        seen.add(key);
        // Fresh staging ids so multi-file merges stay unique.
        additions.push({
          ...profile,
          id: `import:${additions.length}:${profile.sourcePath}`,
        });
      }
    } catch (e) {
      rejected.push({ name: file.name, reason: String((e as Error)?.message || e) });
    }
  }

  return { additions, duplicates, rejected, sources };
}

/** Design: `xeovo-random` is the pinned auto-picker, not a real endpoint. */
export const RANDOM_PROFILE_NAME = 'xeovo-random';
/** Synthetic id for the virtual auto-picker row (never persisted). */
export const VIRTUAL_RANDOM_ID = 'virtual:xeovo-random';

/**
 * Auto-picker / “random” rows: exact `xeovo-random`, variants like
 * `xeovo-random-tcp`, and any segment `random` (e.g. `provider-random-udp`).
 */
export function isRandomProfileName(name: string): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return false;
  if (n === RANDOM_PROFILE_NAME || n === 'random') return true;
  if (n.startsWith(`${RANDOM_PROFILE_NAME}-`) || n.startsWith(`${RANDOM_PROFILE_NAME}_`)) return true;
  return /(^|[-_])random([-_]|$)/.test(n);
}

export function isVirtualRandomProfile(profile: VpnProfile | null | undefined): boolean {
  return !!profile && profile.id === VIRTUAL_RANDOM_ID;
}

/**
 * Rail group for a profile. Prefers the import-time bundle label; falls back to
 * a stable kind/vendor heuristic so older stores still group sensibly.
 */
export function profileBundleLabel(profile: VpnProfile): string {
  const explicit = profile.bundle?.trim();
  if (explicit) return explicit;
  if (isVirtualRandomProfile(profile)) return 'Pinned';
  if (/^xeovo/i.test(profile.name)) {
    return profile.kind === 'openvpn' ? 'Xeovo · OpenVPN' : 'Xeovo · WireGuard';
  }
  return profile.kind === 'openvpn' ? 'OpenVPN' : 'WireGuard';
}

/** Insert a non-persisted `xeovo-random` pin when real WireGuard peers exist. */
export function withVirtualRandom(profiles: VpnProfile[]): VpnProfile[] {
  const hasRealWg = profiles.some(p => p.kind === 'wireguard' && !isRandomProfileName(p.name));
  // Only a WireGuard random covers connect-time auto-pick; OpenVPN random is preview-only.
  const hasWgRandom = profiles.some(p => p.kind === 'wireguard' && isRandomProfileName(p.name));
  if (!hasRealWg || hasWgRandom) return profiles;
  const virtual: VpnProfile = {
    id: VIRTUAL_RANDOM_ID,
    name: RANDOM_PROFILE_NAME,
    sourcePath: 'virtual://xeovo-random',
    kind: 'wireguard',
    configText: '', // connect always resolves to a measured peer
    bundle: 'Pinned',
  };
  return [virtual, ...profiles];
}

/**
 * Resolve which WireGuard profile `xeovo-random` should actually connect.
 * Requires measured latencies so the UI never invents a "fastest" peer.
 */
export function pickFastestPeer(
  profiles: VpnProfile[],
  latencies: Record<string, number | null | undefined>,
): VpnProfile | null {
  const peers = profiles.filter(p => p.kind === 'wireguard' && !isRandomProfileName(p.name));
  const measured = peers.filter(p => typeof latencies[p.id] === 'number' && Number.isFinite(latencies[p.id]!));
  if (!measured.length) return null;
  return [...measured].sort((a, b) => (latencies[a.id] as number) - (latencies[b.id] as number))[0] ?? null;
}

/** Line-oriented view model for the structured config renderer. */
export type ConfLine =
  | { kind: 'section'; text: string }
  | { kind: 'kv'; key: string; value: string; secret: boolean }
  | { kind: 'raw'; text: string };

const SECRET_KEYS = /^(privatekey|presharedkey|key|pkcs12|auth-user-pass)$/i;

export function parseConfLines(text: string): ConfLine[] {
  const redacted = redactVpnProfileSecrets(text);
  return redacted.split(/\r?\n/).map(line => {
    const trimmed = line.trim();
    if (/^\[[^\]]+\]$/.test(trimmed)) return { kind: 'section', text: trimmed };
    const eq = line.match(/^(\s*)([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*)$/);
    if (eq) {
      return {
        kind: 'kv',
        key: eq[2],
        value: eq[3],
        secret: SECRET_KEYS.test(eq[2]) || /\[hidden\]/i.test(eq[3]),
      };
    }
    return { kind: 'raw', text: line };
  });
}

export function formatUptime(secs: number | null | undefined): string | null {
  if (secs == null || !Number.isFinite(secs) || secs < 0) return null;
  const s = Math.floor(secs);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(r).padStart(2, '0')}s`;
  return `${r}s`;
}
