import React, { useCallback, useEffect, useState } from 'react';
import { Lock, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wifi, WifiOff, X } from 'lucide-react';

type VpnStatus = Record<string, unknown>;
type ConfirmAction = 'connect' | 'restore' | 'disable-killswitch' | 'recover' | null;

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
  const [confirm, setConfirm] = useState<ConfirmAction>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const nativeControls = Boolean(
    window.api.vpnConnect && window.api.vpnDisconnect &&
    window.api.vpnSetKillswitch && window.api.vpnRecover,
  );

  const refresh = useCallback(async () => {
    if (!window.api.vpnStatus) { setError('VPN controls require the native Tauri shell.'); return; }
    try { setStatus(await window.api.vpnStatus()); setError(''); }
    catch (e) { setError(String(e)); }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const run = async () => {
    const action = confirm;
    setConfirm(null);
    if (!action) return;
    setBusy(true); setError('');
    try {
      if (action === 'connect') {
        if (!window.api.vpnConnect) throw new Error('VPN mutations require the trusted native host window.');
        if (!configText.trim()) throw new Error('Paste a WireGuard configuration first.');
        await window.api.vpnConnect(configText);
      } else if (action === 'restore') {
        if (!window.api.vpnDisconnect) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnDisconnect(true);
      } else if (action === 'disable-killswitch') {
        if (!window.api.vpnSetKillswitch) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnSetKillswitch(false);
      } else if (action === 'recover') {
        if (!window.api.vpnRecover) throw new Error('VPN mutations require the trusted native host window.');
        await window.api.vpnRecover();
      }
      await refresh();
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };

  const phase = String(status?.phase ?? 'unknown');
  const egress = String(status?.egress ?? 'unknown');
  const connected = phase === 'connected';
  const blocked = egress === 'blocked';
  const killSwitch = status?.killswitch_active === true;
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

      <div className="border border-xmr-border/50 bg-xmr-surface/40 p-5">
        <div className="flex items-center gap-3">
          <Icon size={26} className={accent} />
          <div className="flex-1">
            <div className={`text-sm font-black uppercase tracking-wider ${accent}`}>{phaseLabels[phase] ?? phase}</div>
            <div className="mt-1 text-[10px] text-xmr-dim">{connected ? `interface ${String(status?.interface ?? 'unknown')}` : 'WireGuard broker status'}</div>
          </div>
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

      <div className="border border-xmr-border/50 bg-xmr-surface/20 p-5">
        <label className="text-[10px] font-black uppercase tracking-widest text-xmr-dim">WireGuard configuration</label>
        <textarea value={configText} onChange={e => setConfigText(e.target.value)} rows={8} spellCheck={false} placeholder="[Interface]\nPrivateKey = …\n[Peer]\nPublicKey = …" className="mt-2 w-full resize-y border border-xmr-border bg-xmr-base p-3 font-mono text-[10px] text-xmr-text outline-none focus:border-xmr-green" />
        <button onClick={() => setConfirm('connect')} disabled={busy || !nativeControls || !configText.trim()} className="mt-3 w-full border border-xmr-green/50 bg-xmr-green/10 px-4 py-3 text-[11px] font-black uppercase tracking-widest text-xmr-green hover:bg-xmr-green/20 disabled:opacity-40">Connect VPN</button>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={() => setConfirm('restore')} disabled={busy || !nativeControls || !connected} className="border border-xmr-accent/50 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-xmr-accent disabled:opacity-40">Disconnect + restore clearnet</button>
        <button onClick={() => setConfirm('disable-killswitch')} disabled={busy || !nativeControls || !killSwitch} className="border border-red-500/50 px-3 py-2 text-[10px] font-black uppercase tracking-wider text-red-400 disabled:opacity-40">Disable kill-switch</button>
        <button onClick={() => setConfirm('recover')} disabled={busy || !nativeControls} className="border border-xmr-border px-3 py-2 text-[10px] font-black uppercase tracking-wider text-xmr-dim hover:text-xmr-green disabled:opacity-40">Recover blocked state</button>
      </div>

      {!nativeControls && <p className="border border-xmr-border/50 bg-xmr-surface/20 p-3 text-[10px] leading-relaxed text-xmr-dim">This embedded ROS view can inspect VPN status, but mutations are available only in the trusted native host window.</p>}
      <p className="text-[10px] leading-relaxed text-xmr-dim">The embedded RipleyOS view can read status only. These controls run in the trusted native shell; the broker validates the configuration, applies the kill-switch before routes, and asks Polkit before connect or clearnet restoration.</p>
      {error && <div className="border border-red-500/40 bg-red-500/5 p-3 text-[10px] text-red-400">{error}</div>}

      {confirm && <Confirm action={confirm} onCancel={() => setConfirm(null)} onConfirm={run} />}
    </div>
  );
}

function Confirm({ action, onCancel, onConfirm }: { action: Exclude<ConfirmAction, null>; onCancel: () => void; onConfirm: () => void }) {
  const copy: Record<Exclude<ConfirmAction, null>, [string, string]> = {
    connect: ['Connect VPN?', 'This changes routing for the whole computer. The broker installs a host-wide fail-closed block before bringing up WireGuard.'],
    restore: ['Restore clearnet?', 'This re-opens non-VPN networking for the whole computer after disconnecting the tunnel.'],
    'disable-killswitch': ['Disable kill-switch?', 'This removes the host-wide block. Traffic from any app may leave over clearnet if the VPN is not connected.'],
    recover: ['Recover blocked state?', 'The broker will reconcile the whole computer toward an offline, blocked state.'],
  };
  const [title, body] = copy[action];
  return <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-6" role="dialog" aria-modal="true">
    <div className="w-full max-w-sm border border-xmr-green/40 bg-xmr-base p-5 shadow-2xl">
      <div className="flex items-center justify-between"><h3 className="text-sm font-black uppercase tracking-widest text-xmr-green">{title}</h3><button onClick={onCancel} className="text-xmr-dim hover:text-xmr-text"><X size={15} /></button></div>
      <p className="mt-4 text-xs leading-relaxed text-xmr-dim">{body}</p>
      <div className="mt-5 flex justify-end gap-2"><button onClick={onCancel} className="border border-xmr-border px-3 py-2 text-[10px] font-black uppercase text-xmr-dim">Cancel</button><button onClick={onConfirm} className="border border-xmr-green/50 bg-xmr-green/10 px-3 py-2 text-[10px] font-black uppercase text-xmr-green">Confirm</button></div>
    </div>
  </div>;
}

export default VpnView;
