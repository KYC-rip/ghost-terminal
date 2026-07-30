import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Lock, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wifi, WifiOff, X } from 'lucide-react';
import { readVpnProfileFile, redactVpnProfileSecrets, type VpnProfile } from '../vpnProfiles';

type VpnStatus = Record<string, unknown>;
type ConfirmAction = 'connect' | 'disconnect-blocked' | 'restore' | 'disable-killswitch' | 'recover' | 'emergency-restore' | null;

const phaseLabels: Record<string, string> = {
  disconnected_open: 'Disconnected · clearnet open',
  disconnected_blocked: 'Disconnected · blocked',
  connecting_blocked: 'Connecting · blocked',
  connected: 'Connected',
  degraded_blocked: 'Degraded · blocked',
  error_blocked: 'Error · blocked',
};

function age(value: unknown): string {
  const seconds = typeof value === 'number' && Number.isFinite(value) ? value : null;
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.max(0, Math.floor(seconds))}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

/** Native, host-owned VPN controls. The embedded ROS app is deliberately read-only. */
export function VpnView() {
  const [status, setStatus] = useState<VpnStatus | null>(null);
  const [configText, setConfigText] = useState('');
  const [profiles, setProfiles] = useState<VpnProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<ConfirmAction>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [statusError, setStatusError] = useState('');
  const [profilesPersisted, setProfilesPersisted] = useState(false);
  const configFile = useRef<HTMLInputElement | null>(null);
  const nativeControls = Boolean(
    window.api.vpnConnect && window.api.vpnDisconnect &&
    window.api.vpnSetKillswitch && window.api.vpnRecover,
  );

  const refresh = useCallback(async () => {
    if (!window.api.vpnStatus) { setStatusError('VPN controls require the native Tauri shell.'); return; }
    try { setStatus(await window.api.vpnStatus()); setStatusError(''); }
    catch (e) { setStatusError(String(e)); }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (!window.api.vpnProfilesLoad) return;
    void window.api.vpnProfilesLoad()
      .then(store => {
        if (!store?.profiles.length) return;
        const selected = store.profiles.find(profile => profile.id === store.selectedProfileId)
          ?? store.profiles[0];
        setProfiles(store.profiles);
        setSelectedProfileId(selected.id);
        setConfigText(selected.configText);
        setProfilesPersisted(true);
      })
      .catch(e => setError(`Stored profiles could not be unlocked: ${String(e)}`));
  }, []);

  const persistProfiles = async (nextProfiles: VpnProfile[], selectedProfileId: string | null) => {
    if (!window.api.vpnProfilesSave) {
      setProfilesPersisted(false);
      throw new Error('Encrypted profile storage requires the trusted native host window.');
    }
    await window.api.vpnProfilesSave({ v: 1, profiles: nextProfiles, selectedProfileId });
    setProfilesPersisted(true);
  };

  const run = async () => {
    const action = confirm;
    if (!action) return;
    setBusy(true); setError('');
    try {
      if (action === 'connect') {
        if (!window.api.vpnConnect) throw new Error('VPN mutations require the trusted native host window.');
        if (!configText.trim()) throw new Error('Paste a WireGuard configuration first.');
        await window.api.vpnConnect(configText, selectedProfile?.name);
      } else if (action === 'disconnect-blocked') {
        if (!window.api.vpnDisconnect) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnDisconnect(false);
      } else if (action === 'restore') {
        if (!window.api.vpnDisconnect) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnDisconnect(true);
      } else if (action === 'disable-killswitch') {
        if (!window.api.vpnSetKillswitch) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnSetKillswitch(false);
      } else if (action === 'recover') {
        if (!window.api.vpnRecover) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnRecover();
      } else if (action === 'emergency-restore') {
        if (!window.api.vpnEmergencyRestore) throw new Error('Emergency recovery is unavailable in this native build.');
        await window.api.vpnEmergencyRestore();
      }
      await refresh();
      setConfirm(null);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };

  const phase = String(status?.phase ?? 'unknown');
  const egress = String(status?.egress ?? 'unknown');
  const connected = phase === 'connected';
  const tunnelActive = typeof status?.interface === 'string' && status.interface.length > 0;
  const blocked = egress === 'blocked';
  const killSwitch = status?.killswitch_active === true;
  const cleanupRequired = status?.cleanup_required === true;
  const selectedProfile = profiles.find(p => p.id === selectedProfileId) ?? null;
  const activeProfileName = typeof status?.profile_name === 'string' && status.profile_name.trim()
    ? status.profile_name.trim()
    : null;
  const Icon = connected ? ShieldCheck : blocked ? ShieldAlert : Shield;
  const accent = connected ? 'text-xmr-green' : blocked ? 'text-xmr-accent' : 'text-xmr-dim';

  return (
    <div className="max-w-2xl space-y-5">
      <div className="flex items-center justify-between border-b border-xmr-border/30 pb-4">
        <div>
          <h2 className="text-sm font-black uppercase tracking-[0.25em] text-xmr-green">VPN_CONTROL</h2>
          <p className="mt-1 text-[10px] uppercase tracking-widest text-xmr-dim">WireGuard · fail-closed egress</p>
        </div>
        <button onClick={refresh} disabled={busy} className="border border-xmr-border px-2 py-2 text-xmr-dim hover:text-xmr-green disabled:opacity-40" title="Refresh">
          <RefreshCw size={14} className={busy ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Use the bridged host token directly. Tailwind's `/40` color utility
          captures the native renderer's own palette during compilation on some
          WebKit builds, leaving this card black under ROS light skins. */}
      <div className="border border-xmr-border/50 bg-[var(--bg-panel)] p-5">
        <div className="flex items-center gap-3">
          <Icon size={26} className={accent} />
          <div className="flex-1">
            <div className={`text-sm font-black uppercase tracking-wider ${accent}`}>{phaseLabels[phase] ?? phase}</div>
            <div className="mt-1 text-[10px] text-xmr-dim">
              {connected
                ? `${activeProfileName ? `${activeProfileName} · ` : ''}${String(status?.backend ?? 'WireGuard')} · interface ${String(status?.interface ?? 'unknown')}`
                : String(status?.backend ?? 'WireGuard broker status')}
            </div>
          </div>
          {connected && (
            <button
              type="button"
              onClick={() => setConfirm('restore')}
              disabled={busy || !nativeControls}
              className="inline-flex shrink-0 items-center gap-1.5 border border-xmr-accent/50 bg-xmr-accent/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-xmr-accent hover:bg-xmr-accent/20 disabled:opacity-40"
              title="Disconnect the VPN and restore host-wide clearnet"
            >
              <WifiOff size={12} />
              Disconnect
            </button>
          )}
        </div>
        <div className="mt-5 grid grid-cols-2 gap-3 text-[10px] uppercase tracking-wider">
          <div className="border-t border-xmr-border/30 pt-2 text-xmr-dim">Egress
            <div className={blocked ? 'mt-1 text-xmr-accent' : 'mt-1 text-xmr-green'}>{blocked ? <><WifiOff size={12} className="mr-1 inline" />BLOCKED</> : <><Wifi size={12} className="mr-1 inline" />OPEN</>}</div>
          </div>
          <div className="border-t border-xmr-border/30 pt-2 text-xmr-dim">Kill-switch
            <div className={killSwitch ? 'mt-1 text-xmr-green' : 'mt-1 text-xmr-dim'}><Lock size={12} className="mr-1 inline" />{killSwitch ? 'ACTIVE' : 'OFF'}</div>
          </div>
          {connected && <div className="border-t border-xmr-border/30 pt-2 text-xmr-dim">Last handshake<div className="mt-1 text-xmr-text">{age(status?.handshake_age_secs)}</div></div>}
        </div>
      </div>

      <div className="border border-xmr-accent/40 bg-xmr-accent/5 p-4 text-[10px] leading-relaxed text-xmr-dim">
        <strong className="text-xmr-accent">HOST-WIDE NETWORK CONTROL.</strong>{' '}
        WireGuard routes and the kill-switch apply to the whole computer, not just RipleyOS.
        Other apps and users on this machine may be routed through the VPN or blocked until the
        tunnel is restored or clearnet is explicitly reopened.
      </div>

      <div className="border border-xmr-border/50 bg-[var(--bg-panel)] p-5">
        <div className="flex items-center justify-between gap-3">
          <label className="text-[10px] font-black uppercase tracking-widest text-xmr-dim">VPN profiles</label>
          <button type="button" onClick={() => configFile.current?.click()} className="border border-xmr-border px-2 py-1 text-[9px] font-black uppercase tracking-wider text-xmr-dim hover:text-xmr-green">Import profile bundle</button>
          <input ref={configFile} type="file" accept=".conf,.ovpn,.zip,text/plain,application/zip" className="hidden" onChange={async e => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = '';
            if (!file) return;
            try {
              const loaded = await readVpnProfileFile(file);
              await persistProfiles(loaded, loaded[0].id);
              setProfiles(loaded);
              setSelectedProfileId(loaded[0].id);
              setConfigText(loaded[0].configText);
              setError('');
            }
            catch (err) { setError(String(err)); }
          }} />
        </div>
        {tunnelActive && (
          <div className="mt-3 border border-xmr-green/40 bg-xmr-green/5 px-3 py-2 text-[9px] leading-relaxed text-xmr-dim">
            {activeProfileName
              ? <><b className="text-xmr-green">ACTIVE PROFILE:</b> {activeProfileName}</>
              : <><b className="text-xmr-accent">ACTIVE PROFILE UNKNOWN.</b> This tunnel was connected before profile tracking was added. Reconnect once to bind its imported profile name.</>}
          </div>
        )}
        <div className={`mt-3 ${profiles.length ? 'grid grid-cols-[170px_minmax(0,1fr)] gap-3' : ''}`}>
          {profiles.length > 0 && (
            <aside className="max-h-64 space-y-1 overflow-y-auto border border-xmr-border/60 bg-xmr-base p-1" aria-label="Imported VPN profiles">
              {profiles.map(profile => {
                const isActive = connected && activeProfileName === profile.name;
                return (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => {
                    setSelectedProfileId(profile.id);
                    setConfigText(profile.configText);
                    setError('');
                    void persistProfiles(profiles, profile.id)
                      .catch(err => setError(`Profile selection was not persisted: ${String(err)}`));
                  }}
                  className={`w-full border px-2 py-2 text-left ${isActive ? 'border-xmr-green bg-xmr-green/15' : selectedProfileId === profile.id ? 'border-xmr-green/70 bg-xmr-green/10' : 'border-transparent hover:border-xmr-border'}`}
                  title={profile.sourcePath}
                >
                  <span className="flex items-center justify-between gap-2 text-[10px] font-bold text-xmr-text">
                    <span className="truncate">{profile.name}</span>
                    {isActive && <span className="shrink-0 text-[7px] font-black uppercase tracking-widest text-xmr-green">Active</span>}
                  </span>
                  <span className={`mt-1 block text-[8px] font-black uppercase tracking-widest ${profile.kind === 'wireguard' ? 'text-xmr-green' : 'text-xmr-accent'}`}>
                    {profile.kind === 'wireguard' ? 'WireGuard' : 'OpenVPN · preview'}
                  </span>
                </button>
                );
              })}
            </aside>
          )}
          <div className="min-w-0">
            {selectedProfile?.kind === 'openvpn' ? (
              <div className="flex min-h-48 flex-col justify-center border border-xmr-accent/40 bg-xmr-accent/5 p-4">
                <b className="text-[10px] uppercase tracking-widest text-xmr-accent">OpenVPN profile loaded</b>
                <p className="mt-2 text-[10px] leading-relaxed text-xmr-dim">
                  This profile is kept in memory and can be inspected in the sidebar, but it cannot
                  be connected by the current WireGuard-only broker. TCP OpenVPN-over-Tor needs its
                  own broker state machine and kill-switch policy.
                </p>
              </div>
            ) : selectedProfile ? (
              <pre className="min-h-48 max-h-64 overflow-auto whitespace-pre-wrap break-all border border-xmr-border bg-xmr-base p-3 font-mono text-[10px] text-xmr-text">
                {redactVpnProfileSecrets(configText)}
              </pre>
            ) : (
              <textarea
                value={configText}
                onChange={e => { setSelectedProfileId(null); setConfigText(e.target.value); }}
                rows={8}
                spellCheck={false}
                placeholder="[Interface]\nPrivateKey = …\n[Peer]\nPublicKey = …"
                className="w-full resize-y border border-xmr-border bg-xmr-base p-3 font-mono text-[10px] text-xmr-text outline-none focus:border-xmr-green"
              />
            )}
            <button
              onClick={() => setConfirm(tunnelActive ? 'restore' : 'connect')}
              disabled={busy || !nativeControls || (!tunnelActive && (!configText.trim() || selectedProfile?.kind === 'openvpn'))}
              className={`mt-3 w-full border px-4 py-3 text-[11px] font-black uppercase tracking-widest disabled:opacity-40 ${tunnelActive ? 'border-xmr-accent/50 bg-xmr-accent/10 text-xmr-accent hover:bg-xmr-accent/20' : 'border-xmr-green/50 bg-xmr-green/10 text-xmr-green hover:bg-xmr-green/20'}`}
            >
              {tunnelActive
                ? `Disconnect${activeProfileName ? ` ${activeProfileName}` : ''} + restore clearnet`
                : selectedProfile?.kind === 'openvpn' ? 'OpenVPN broker required' : 'Connect selected profile'}
            </button>
          </div>
        </div>
        <p className="mt-2 text-[9px] leading-relaxed text-xmr-dim">
          Accepted bundles: ZIP containing up to 128 <code>.conf</code>/<code>.ovpn</code> profiles.
          Archive paths, decompressed sizes and UTF-8 text are validated; nothing is extracted to
          disk. {profilesPersisted
            ? 'The imported bundle is encrypted at rest with a native device key. '
            : 'Imported profiles are not stored until native encryption succeeds. '}
          WireGuard hooks are rejected again by the root broker before use.
        </p>
        {profiles.length > 0 && (
          <button
            type="button"
            className="mt-2 text-[9px] font-black uppercase tracking-wider text-red-400 hover:underline"
            onClick={async () => {
              try {
                await window.api.vpnProfilesClear?.();
                setProfiles([]);
                setSelectedProfileId(null);
                setConfigText('');
                setProfilesPersisted(false);
                setError('');
              } catch (e) { setError(`Could not forget stored profiles: ${String(e)}`); }
            }}
          >
            Forget imported profiles
          </button>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={() => setConfirm('disconnect-blocked')} disabled={busy || !nativeControls || !tunnelActive} className="border border-xmr-green/50 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-xmr-green disabled:opacity-40">Disconnect + stay blocked</button>
        <button onClick={() => setConfirm('restore')} disabled={busy || !nativeControls || !tunnelActive} className="border border-xmr-accent/50 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-xmr-accent disabled:opacity-40">Disconnect + restore clearnet</button>
        <button onClick={() => setConfirm('disable-killswitch')} disabled={busy || !nativeControls || !killSwitch} className="border border-red-500/50 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-red-400 disabled:opacity-40">Disable kill-switch</button>
        <button onClick={() => setConfirm('recover')} disabled={busy || !nativeControls} className="border border-xmr-border px-3 py-2 text-[10px] font-black uppercase tracking-wider text-xmr-dim hover:text-xmr-green disabled:opacity-40">Recover blocked state</button>
        {cleanupRequired && <button onClick={() => setConfirm('emergency-restore')} disabled={busy || !window.api.vpnEmergencyRestore} className="border border-red-500/60 bg-red-500/5 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-red-400 disabled:opacity-40">Emergency restore clearnet</button>}
      </div>

      {!nativeControls && <p className="border border-xmr-border/50 bg-[var(--bg-panel)] p-3 text-[10px] leading-relaxed text-xmr-dim">This embedded ROS view can inspect VPN status, but mutations are available only in the trusted native host window.</p>}
      <p className="text-[10px] leading-relaxed text-xmr-dim">The embedded RipleyOS view can read status only. These controls run in the trusted native shell; the privileged backend validates the configuration, applies the kill-switch before routes, and requires native administrator authorization for host-wide changes.</p>
      <p className="text-[10px] leading-relaxed text-xmr-dim">A first connection must produce a WireGuard handshake within 15 seconds. If it does not, the attempted tunnel and Ripley PF anchor are removed automatically; the exact failure and restoration result are written to the integrated system console under <b>VPN</b>.</p>
      {(statusError || error) && <div className="border border-red-500/40 bg-red-500/5 p-3 text-[10px] text-red-400">{statusError || error}</div>}

      {confirm && <Confirm action={confirm} busy={busy} error={error} onCancel={() => !busy && setConfirm(null)} onConfirm={run} />}
    </div>
  );
}

function Confirm({ action, busy, error, onCancel, onConfirm }: {
  action: Exclude<ConfirmAction, null>;
  busy: boolean;
  error: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const copy: Record<Exclude<ConfirmAction, null>, [string, string]> = {
    connect: ['Connect VPN?', 'This changes routing for the whole computer. The broker installs a host-wide fail-closed block before bringing up WireGuard.'],
    'disconnect-blocked': ['Disconnect and stay blocked?', 'This tears down WireGuard but keeps the host-wide egress block. Other apps remain offline until you explicitly restore clearnet or reconnect.'],
    restore: ['Restore clearnet?', 'This re-opens non-VPN networking for the whole computer after disconnecting the tunnel.'],
    'disable-killswitch': ['Disable kill-switch?', 'This removes the host-wide block. Traffic from any app may leave over clearnet if the VPN is not connected.'],
    recover: ['Recover blocked state?', 'The broker will reconcile the whole computer toward an offline, blocked state.'],
    'emergency-restore': ['Emergency restore clearnet?', 'BREAK GLASS: force teardown and remove the host-wide block despite dirty cleanup state. Other apps may immediately resume clearnet traffic. Polkit authorization is required.'],
  };
  const [title, body] = copy[action];
  return <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-6" role="dialog" aria-modal="true">
    <div className="w-full max-w-sm border border-xmr-green/40 bg-xmr-base p-5 shadow-2xl">
      <div className="flex items-center justify-between"><h3 className="text-sm font-black uppercase tracking-widest text-xmr-green">{title}</h3><button onClick={onCancel} disabled={busy} className="text-xmr-dim hover:text-xmr-text disabled:opacity-40"><X size={15} /></button></div>
      <p className="mt-4 text-xs leading-relaxed text-xmr-dim">{body}</p>
      {error && <p className="mt-4 border border-red-500/40 bg-red-500/5 p-3 text-[10px] leading-relaxed text-red-400">{error}</p>}
      <div className="mt-5 flex justify-end gap-2"><button onClick={onCancel} disabled={busy} className="border border-xmr-border px-3 py-2 text-[10px] font-black uppercase text-xmr-dim disabled:opacity-40">Cancel</button><button onClick={onConfirm} disabled={busy} className="border border-xmr-green/50 bg-xmr-green/10 px-3 py-2 text-[10px] font-black uppercase text-xmr-green disabled:opacity-40">{busy ? 'Authorizing…' : 'Confirm'}</button></div>
    </div>
  </div>;
}

export default VpnView;
