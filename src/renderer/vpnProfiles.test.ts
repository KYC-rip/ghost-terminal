import { describe, expect, it } from 'vitest';
import { strToU8, zipSync } from 'fflate';
import {
  bundleLabelFromSource, formatUptime, isRandomProfileName, parseConfLines, pickFastestPeer,
  profileBundleLabel, readVpnProfileBytes, redactVpnProfileSecrets, stageVpnImport,
  withVirtualRandom, type VpnProfile,
} from './vpnProfiles';

const wg = `[Interface]
PrivateKey = ${'A'.repeat(44)}
Address = 10.0.0.2/32
[Peer]
PublicKey = ${'B'.repeat(44)}
AllowedIPs = 0.0.0.0/0
`;
const ovpn = 'client\nremote vpn.example 443 tcp\n<ca>\ncertificate\n</ca>\n';

describe('VPN profile bundles', () => {
  it('never exposes WireGuard or inline OpenVPN secrets in a preview', () => {
    const preview = redactVpnProfileSecrets(`${wg}
PresharedKey = ${'C'.repeat(44)}
<key>
PRIVATE MATERIAL
</key>`);
    expect(preview).not.toContain('A'.repeat(44));
    expect(preview).not.toContain('C'.repeat(44));
    expect(preview).not.toContain('PRIVATE MATERIAL');
    expect(preview).toContain('PublicKey');
    expect(preview.match(/\[hidden\]/g)).toHaveLength(3);
  });

  it('imports and switches between WireGuard and OpenVPN profile metadata', async () => {
    const zip = zipSync({
      'profiles/ch-zurich.conf': strToU8(wg),
      'profiles/nl-amsterdam.ovpn': strToU8(ovpn),
      'README.txt': strToU8('ignored'),
    });
    const profiles = await readVpnProfileBytes('xeovo-pack.zip', zip);
    expect(profiles.map(p => [p.name, p.kind, p.bundle])).toEqual([
      ['ch-zurich', 'wireguard', 'xeovo-pack'],
      ['nl-amsterdam', 'openvpn', 'xeovo-pack'],
    ]);
  });

  it('rejects traversal names even though profiles are never written to disk', async () => {
    const zip = zipSync({ '../escape.conf': strToU8(wg) });
    await expect(readVpnProfileBytes('bundle.zip', zip)).rejects.toThrow(/Unsafe profile path/);
  });

  it('rejects decompression bombs before retaining oversized profile text', async () => {
    const zip = zipSync({ 'huge.conf': strToU8(`${wg}\n#${'x'.repeat(20 * 1024)}`) });
    // Soft-skip the oversized entry; with nothing left the archive is rejected.
    await expect(readVpnProfileBytes('bundle.zip', zip)).rejects.toThrow(/16 KiB|No valid profiles/);
  });

  it('refuses bundles without supported profile files', async () => {
    const zip = zipSync({ 'README.txt': strToU8('nothing here') });
    await expect(readVpnProfileBytes('bundle.zip', zip)).rejects.toThrow(/no .conf or .ovpn/);
  });
});

describe('xeovo-random peer selection', () => {
  const peer = (id: string, name: string): VpnProfile => ({
    id, name, sourcePath: `${name}.conf`, kind: 'wireguard', configText: wg,
  });

  it('recognises the pinned random profile name and protocol variants', () => {
    expect(isRandomProfileName('xeovo-random')).toBe(true);
    expect(isRandomProfileName('XEOVO-RANDOM')).toBe(true);
    expect(isRandomProfileName('xeovo-random-tcp')).toBe(true);
    expect(isRandomProfileName('xeovo-random-udp')).toBe(true);
    expect(isRandomProfileName('provider-random')).toBe(true);
    expect(isRandomProfileName('xeovo-al')).toBe(false);
    expect(isRandomProfileName('xeovo-fi-tcp')).toBe(false);
  });

  it('labels each import source as its own bundle group', () => {
    expect(bundleLabelFromSource('xeovo-random-tcp.ovpn.zip')).toBe('xeovo-random-tcp');
    expect(bundleLabelFromSource('xeovo.zip')).toBe('xeovo');
    const ov: VpnProfile = {
      id: '1', name: 'xeovo-fi-tcp', sourcePath: 'xeovo-fi-tcp.ovpn', kind: 'openvpn',
      configText: ovpn, bundle: 'xeovo-random-tcp',
    };
    expect(profileBundleLabel(ov)).toBe('xeovo-random-tcp');
    // Older stores without bundle still group by vendor + protocol.
    expect(profileBundleLabel({ ...ov, bundle: undefined })).toBe('Xeovo · OpenVPN');
  });

  it('picks the lowest measured latency and ignores random itself', () => {
    const profiles = [
      peer('r', 'xeovo-random'),
      peer('a', 'xeovo-al'),
      peer('f', 'xeovo-fi'),
      peer('c', 'xeovo-ch'),
    ];
    const best = pickFastestPeer(profiles, { r: 1, a: 80, f: 24, c: 42 });
    expect(best?.name).toBe('xeovo-fi');
  });

  it('returns null when speeds have not been measured', () => {
    const profiles = [peer('r', 'xeovo-random'), peer('a', 'xeovo-al')];
    expect(pickFastestPeer(profiles, {})).toBeNull();
  });

  it('injects a virtual random pin when real peers exist', () => {
    const withPin = withVirtualRandom([peer('a', 'xeovo-al')]);
    expect(withPin[0].name).toBe('xeovo-random');
    expect(withPin[0].id.startsWith('virtual:')).toBe(true);
    // Already has a WireGuard random — do not duplicate.
    expect(withVirtualRandom([peer('r', 'xeovo-random'), peer('a', 'xeovo-al')])).toHaveLength(2);
    // OpenVPN random does not cover WireGuard auto-pick — still inject WG pin.
    const ovRandom: VpnProfile = {
      id: 'ov', name: 'xeovo-random-tcp', sourcePath: 'x.ovpn', kind: 'openvpn', configText: ovpn,
    };
    const mixed = withVirtualRandom([ovRandom, peer('a', 'xeovo-al')]);
    expect(mixed[0].id.startsWith('virtual:')).toBe(true);
    expect(mixed.some(p => p.name === 'xeovo-random-tcp')).toBe(true);
    // No peers — no pin.
    expect(withVirtualRandom([])).toHaveLength(0);
  });
});

describe('conf display helpers', () => {
  it('formats uptime compactly', () => {
    expect(formatUptime(9)).toBe('9s');
    expect(formatUptime(75)).toBe('1m 15s');
    expect(formatUptime(3723)).toBe('1h 02m');
    expect(formatUptime(null)).toBeNull();
  });

  it('structures redacted WireGuard config lines', () => {
    const lines = parseConfLines(`${wg}PresharedKey = ${'C'.repeat(44)}\n`);
    expect(lines.some(l => l.kind === 'section' && l.text === '[Interface]')).toBe(true);
    const secret = lines.find(l => l.kind === 'kv' && l.key === 'PrivateKey');
    expect(secret && secret.kind === 'kv' && secret.secret).toBe(true);
    expect(secret && secret.kind === 'kv' && secret.value).toContain('[hidden]');
  });
});

describe('import staging', () => {
  it('classifies additions, duplicates, and rejects without overwriting', async () => {
    const zip = zipSync({
      'xeovo-al.conf': strToU8(wg),
      'xeovo-fi.conf': strToU8(wg),
      'notes.txt': strToU8('ignored'),
    });
    // File-like objects for the stage helper (only name + arrayBuffer needed).
    const zipFile = {
      name: 'bundle.zip',
      arrayBuffer: async () => zip.buffer.slice(zip.byteOffset, zip.byteOffset + zip.byteLength),
    } as File;
    const junk = {
      name: 'hook.sh',
      arrayBuffer: async () => new TextEncoder().encode('#!/bin/sh\necho bad\n').buffer,
    } as File;

    const stage = await stageVpnImport([zipFile, junk], ['xeovo-al']);
    expect(stage.additions.map(p => p.name)).toEqual(['xeovo-fi']);
    expect(stage.duplicates).toContain('xeovo-al');
    expect(stage.rejected.some(r => r.name === 'hook.sh')).toBe(true);
    // notes.txt inside zip is ignored by the zip reader (not .conf/.ovpn), not a hard reject.
  });
});
