import { describe, expect, it } from 'vitest';
import { strToU8, zipSync } from 'fflate';
import { readVpnProfileBytes, redactVpnProfileSecrets } from './vpnProfiles';

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
    const profiles = await readVpnProfileBytes('bundle.zip', zip);
    expect(profiles.map(p => [p.name, p.kind])).toEqual([
      ['ch-zurich', 'wireguard'],
      ['nl-amsterdam', 'openvpn'],
    ]);
  });

  it('rejects traversal names even though profiles are never written to disk', async () => {
    const zip = zipSync({ '../escape.conf': strToU8(wg) });
    await expect(readVpnProfileBytes('bundle.zip', zip)).rejects.toThrow(/Unsafe profile path/);
  });

  it('rejects decompression bombs before retaining oversized profile text', async () => {
    const zip = zipSync({ 'huge.conf': strToU8(`${wg}\n#${'x'.repeat(20 * 1024)}`) });
    await expect(readVpnProfileBytes('bundle.zip', zip)).rejects.toThrow(/16 KiB/);
  });

  it('refuses bundles without supported profile files', async () => {
    const zip = zipSync({ 'README.txt': strToU8('nothing here') });
    await expect(readVpnProfileBytes('bundle.zip', zip)).rejects.toThrow(/no .conf or .ovpn/);
  });
});
