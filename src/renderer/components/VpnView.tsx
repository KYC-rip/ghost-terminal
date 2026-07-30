import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, ArrowDownUp, Clock, Copy, FileKey2, FolderDown, Gauge, Globe,
  GlobeLock, Loader2, Lock, LockOpen, PanelLeftClose, PanelLeftOpen, PlugZap,
  Power, RefreshCw, Search, Server, Shield, ShieldAlert, ShieldCheck, ShieldOff,
  Shuffle, Trash2, Waypoints, X,
} from 'lucide-react';
import { readVpnProfileFile, redactVpnProfileSecrets, type VpnProfile } from '../vpnProfiles';
import { createVpnTranslator } from '../vpnLocale';
import './VpnView.css';

type VpnStatus = Record<string, unknown>;
type ConfirmAction = 'connect' | 'disconnect-blocked' | 'restore' | 'disable-killswitch' | 'recover' | 'emergency-restore' | null;
type Accent = 'ok' | 'warn' | 'danger';

const phaseLabels: Record<string, string> = {
  disconnected_open: 'Disconnected · clearnet',
  disconnected_blocked: 'Disconnected · blocked',
  connecting_blocked: 'Connecting…',
  connected: 'Connected',
  degraded_blocked: 'Degraded · blocked',
  error_blocked: 'Error · blocked',
};

const regionByCode: Record<string, string> = {
  al: 'Albania', au: 'Australia', br: 'Brazil', ca: 'Canada', ch: 'Switzerland',
  de: 'Germany', fi: 'Finland', fr: 'France', gb: 'United Kingdom', uk: 'United Kingdom', nl: 'Netherlands',
  no: 'Norway', se: 'Sweden', sg: 'Singapore', us: 'United States',
};

function age(value: unknown): string {
  const seconds = typeof value === 'number' && Number.isFinite(value) ? value : null;
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.max(0, Math.floor(seconds))}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function bytes(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${Math.floor(value)} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(value < 10 * 1024 ? 1 : 0)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(value < 10 * 1024 ** 2 ? 1 : 0)} MB`;
  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

function countryFlag(code: string): string | null {
  if (!/^[A-Z]{2}$/.test(code)) return null;
  return String.fromCodePoint(...[...code].map(char => 0x1f1e6 + char.charCodeAt(0) - 65));
}

function profileMeta(profile: VpnProfile): { cc: string; region: string; endpoint: string } {
  const code = profile.name.toLowerCase().match(/(?:^|[-_])([a-z]{2})(?:[-_]|$)/)?.[1] ?? '';
  const flagCode = code === 'uk' ? 'gb' : code;
  const endpoint = profile.configText.match(/^\s*(?:Endpoint|remote)\s*(?:=\s*)?([^\r\n]+)/im)?.[1]?.trim() ?? 'endpoint in profile';
  return {
    cc: flagCode ? flagCode.toUpperCase() : profile.kind === 'openvpn' ? 'OV' : 'WG',
    region: regionByCode[code] ?? (code ? code.toUpperCase() : 'Imported profile'),
    endpoint,
  };
}

function configLine(text: string, key: string): string {
  return text.match(new RegExp(`^\\s*${key}\\s*=\\s*([^\\r\\n]+)`, 'im'))?.[1]?.trim() ?? '—';
}

/** Native, host-owned VPN controls. The embedded ROS app is deliberately read-only. */
export function VpnView() {
  const [locale, setLocale] = useState(() => {
    const query = new URLSearchParams(window.location.search).get('locale');
    return query || (window as Window & { __ripleyVpnLocale?: string }).__ripleyVpnLocale || navigator.language.slice(0, 2);
  });
  const t = useMemo(() => createVpnTranslator(locale), [locale]);
  useEffect(() => {
    const onLocale = (event: Event) => {
      const next = (event as CustomEvent<string>).detail;
      if (typeof next === 'string') setLocale(next);
    };
    window.addEventListener('ripley-vpn-locale-changed', onLocale);
    return () => window.removeEventListener('ripley-vpn-locale-changed', onLocale);
  }, []);
  const [status, setStatus] = useState<VpnStatus | null>(null);
  const [configText, setConfigText] = useState('');
  const [profiles, setProfiles] = useState<VpnProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [confirm, setConfirm] = useState<ConfirmAction>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [statusError, setStatusError] = useState('');
  const [notice, setNotice] = useState('');
  const [profilesPersisted, setProfilesPersisted] = useState(false);
  const [speedTesting, setSpeedTesting] = useState(false);
  const [sortFastest, setSortFastest] = useState(true);
  const [speedTestedAt, setSpeedTestedAt] = useState<number | null>(null);
  const [latencies, setLatencies] = useState<Record<string, number | null>>({});
  const [sideCollapsed, setSideCollapsed] = useState(false);
  const configFile = useRef<HTMLInputElement | null>(null);
  const nativeControls = Boolean(
    window.api.vpnConnect && window.api.vpnDisconnect &&
    window.api.vpnSetKillswitch && window.api.vpnRecover,
  );

  const refresh = useCallback(async () => {
    if (!window.api.vpnStatus) {
      setStatusError('VPN controls require the native Tauri shell.');
      return;
    }
    try {
      setStatus(await window.api.vpnStatus());
      setStatusError('');
    } catch (e) {
      setStatusError(String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (!window.api.vpnProfilesLoad) return;
    void window.api.vpnProfilesLoad()
      .then(store => {
        if (!store?.profiles.length) return;
        const selected = store.profiles.find(profile => profile.id === store.selectedProfileId) ?? store.profiles[0];
        setProfiles(store.profiles);
        setSelectedProfileId(selected.id);
        setConfigText(selected.configText);
        setProfilesPersisted(true);
      })
      .catch(e => setError(`Stored profiles could not be unlocked: ${String(e)}`));
  }, []);

  const persistProfiles = async (nextProfiles: VpnProfile[], nextSelectedId: string | null) => {
    if (!window.api.vpnProfilesSave) {
      setProfilesPersisted(false);
      throw new Error('Encrypted profile storage requires the trusted native host window.');
    }
    await window.api.vpnProfilesSave({ v: 1, profiles: nextProfiles, selectedProfileId: nextSelectedId });
    setProfilesPersisted(true);
  };

  const phase = String(status?.phase ?? 'unknown');
  const egress = String(status?.egress ?? 'unknown');
  const connected = phase === 'connected';
  const tunnelActive = typeof status?.interface === 'string' && status.interface.length > 0;
  const blocked = egress === 'blocked';
  const killSwitch = status?.killswitch_active === true;
  const cleanupRequired = status?.cleanup_required === true;
  const activeProfileName = typeof status?.profile_name === 'string' && status.profile_name.trim()
    ? status.profile_name.trim()
    : null;
  const selectedProfile = profiles.find(profile => profile.id === selectedProfileId) ?? null;
  const selectedMeta = selectedProfile ? profileMeta(selectedProfile) : null;
  const activeProfile = profiles.find(profile => profile.name === activeProfileName) ?? null;
  const accent: Accent = connected ? 'ok' : blocked ? 'warn' : 'danger';
  const HeroIcon = connected ? ShieldCheck : blocked ? ShieldAlert : ShieldOff;

  const filteredProfiles = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return profiles;
    return profiles.filter(profile => {
      const meta = profileMeta(profile);
      return [profile.name, profile.kind, meta.region, meta.cc].some(value => value.toLowerCase().includes(query));
    });
  }, [filter, profiles]);
  const speedSorted = useCallback((items: VpnProfile[]) => {
    if (!sortFastest) return items;
    return [...items].sort((a, b) => {
      if (a.name.toLowerCase() === 'xeovo-random') return -1;
      if (b.name.toLowerCase() === 'xeovo-random') return 1;
      return (latencies[a.id] ?? Number.POSITIVE_INFINITY) - (latencies[b.id] ?? Number.POSITIVE_INFINITY);
    });
  }, [latencies, sortFastest]);
  const pinnedProfiles = speedSorted(filteredProfiles.filter(profile => profile.name.toLowerCase() === 'xeovo-random'));
  const otherProfiles = speedSorted(filteredProfiles.filter(profile => profile.name.toLowerCase() !== 'xeovo-random'));

  const testSpeeds = async () => {
    if (speedTesting) return;
    const candidates = profiles.filter(profile => profile.kind === 'wireguard');
    if (!candidates.length) return;
    if (!window.api.vpnProbeEndpoints) {
      setError('Speed testing requires the current native host build.');
      return;
    }
    setSpeedTesting(true);
    setError('');
    try {
      const endpoints = candidates.map(profile => profileMeta(profile).endpoint);
      const measured = await window.api.vpnProbeEndpoints(endpoints);
      const next: Record<string, number | null> = {};
      candidates.forEach((profile, index) => { next[profile.id] = measured[index] ?? null; });
      setLatencies(next);
      setSpeedTestedAt(Date.now());
    } catch (e) {
      setError(`Could not test server speeds: ${String(e)}`);
    } finally {
      setSpeedTesting(false);
    }
  };

  const selectProfile = (profile: VpnProfile) => {
    setSelectedProfileId(profile.id);
    setConfigText(profile.configText);
    setError('');
    void persistProfiles(profiles, profile.id)
      .catch(err => setError(`Profile selection was not persisted: ${String(err)}`));
  };

  const importProfiles = async (file: File) => {
    const loaded = await readVpnProfileFile(file);
    const names = new Set(profiles.map(profile => profile.name.toLowerCase()));
    const additions = loaded.filter(profile => !names.has(profile.name.toLowerCase()));
    if (!additions.length) {
      setNotice('No profiles added — every imported name already exists.');
      return;
    }
    const next = [...profiles, ...additions];
    const nextSelected = additions[0];
    await persistProfiles(next, nextSelected.id);
    setProfiles(next);
    setSelectedProfileId(nextSelected.id);
    setConfigText(nextSelected.configText);
    setNotice(`Imported ${additions.length} profile${additions.length === 1 ? '' : 's'} · existing names were left unchanged.`);
    setError('');
  };

  const removeProfile = async (profile: VpnProfile) => {
    if (tunnelActive && activeProfileName === profile.name) {
      setError('Disconnect the active profile before removing it.');
      return;
    }
    const next = profiles.filter(item => item.id !== profile.id);
    const fallback = next.find(item => item.id === selectedProfileId) ?? next[0] ?? null;
    try {
      if (next.length) await persistProfiles(next, fallback?.id ?? null);
      else {
        await window.api.vpnProfilesClear?.();
        setProfilesPersisted(false);
      }
      setProfiles(next);
      setSelectedProfileId(fallback?.id ?? null);
      setConfigText(fallback?.configText ?? '');
      setNotice(`Removed ${profile.name}.`);
      setError('');
    } catch (e) {
      setError(`Could not remove ${profile.name}: ${String(e)}`);
    }
  };

  const run = async () => {
    const action = confirm;
    if (!action) return;
    setBusy(true);
    setError('');
    try {
      if (action === 'connect') {
        if (!window.api.vpnConnect) throw new Error('VPN mutations require the trusted native host window.');
        if (!configText.trim()) throw new Error('Choose or paste a WireGuard configuration first.');
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
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const canConnect = nativeControls && !!configText.trim() && selectedProfile?.kind !== 'openvpn';

  return (
    <div className={`vh vh--${accent}${sideCollapsed ? ' is-rail' : ''}`}>
      <aside className="vh__side">
        <div className="vh__stat">
          <span className="vh__statmk" data-accent={accent}>
            {connected ? <ShieldCheck size={16} /> : blocked ? <ShieldAlert size={16} /> : <ShieldOff size={16} />}
          </span>
          <span className="vh__statm">
            <b><span className={`vh__dot ${accent}`} />{connected ? t('connected') : blocked ? t('blocked') : t('clearnet')}</b>
            <span>{activeProfileName ? `${activeProfileName} · tunnel up` : blocked ? 'no tunnel · nothing leaves' : 'no tunnel · direct egress'}</span>
          </span>
          <span className="vh__statacts">
            <button className="vh__ico vh__statrefresh" onClick={() => void refresh()} disabled={busy} title={t('refreshStatus')}>
              <RefreshCw size={13} className={busy ? 'vh__spin' : ''} />
            </button>
            <button className="vh__ico vh__railbtn" onClick={() => setSideCollapsed(value => !value)} title={sideCollapsed ? t('expandSidebar') : t('collapseSidebar')}>
              {sideCollapsed ? <PanelLeftOpen size={14} /> : <PanelLeftClose size={14} />}
            </button>
          </span>
        </div>

        <div className="vh__tools">
          <label className="vh__find">
            <Search size={12} />
            <input value={filter} onChange={event => setFilter(event.target.value)} placeholder={t('filterServers')} spellCheck={false} />
          </label>
          <button className="vh__ico" title={t('importProfiles')} onClick={() => configFile.current?.click()}>
            <FolderDown size={14} />
          </button>
          <input
            ref={configFile}
            type="file"
            accept=".conf,.ovpn,.zip,text/plain,application/zip"
            className="vh__file"
            onChange={async event => {
              const file = event.currentTarget.files?.[0];
              event.currentTarget.value = '';
              if (!file) return;
              try { await importProfiles(file); } catch (e) { setError(String(e)); }
            }}
          />
        </div>
        <div className="vh__phint">
          {profilesPersisted ? t('encryptedMerge') : t('importBegin')}
        </div>
        <div className="vh__probe">
          <button onClick={() => void testSpeeds()} disabled={speedTesting || !profiles.length}>
            {speedTesting ? <Loader2 size={12} className="vh__spin" /> : <Gauge size={12} />}
            {speedTesting ? t('testing') : t('testSpeeds')}
          </button>
          <button className={sortFastest ? 'is-on' : ''} onClick={() => setSortFastest(value => !value)} disabled={!profiles.length}>
            <ArrowDownUp size={12} />{t('fastest')}
          </button>
        </div>
        <div className="vh__probehint">
          {speedTesting
            ? <><Loader2 size={9} className="vh__spin" />{t('probing', { count: profiles.filter(profile => profile.kind === 'wireguard').length })}</>
            : <><Clock size={9} />{speedTestedAt ? t('testedNow') : t('notTested')}{sortFastest ? t('sortedFastest') : ''}</>}
        </div>

        <div className="vh__scroll">
          {pinnedProfiles.length > 0 && <div className="vh__sec">Pinned · {pinnedProfiles.length}</div>}
          {pinnedProfiles.map(profile => (
            <ProfileRow key={profile.id} profile={profile} latency={latencies[profile.id]} tested={speedTestedAt != null && profile.kind === 'wireguard'} selected={profile.id === selectedProfileId} active={connected && profile.name === activeProfileName} onPick={() => selectProfile(profile)} onRemove={() => void removeProfile(profile)} />
          ))}
          <div className="vh__sec">Profiles · {otherProfiles.length}</div>
          {otherProfiles.map(profile => (
            <ProfileRow key={profile.id} profile={profile} latency={latencies[profile.id]} tested={speedTestedAt != null && profile.kind === 'wireguard'} selected={profile.id === selectedProfileId} active={connected && profile.name === activeProfileName} onPick={() => selectProfile(profile)} onRemove={() => void removeProfile(profile)} />
          ))}
          {!filteredProfiles.length && (
            <div className="vh__empty">{profiles.length ? 'No matching profiles.' : 'Import a WireGuard .conf, OpenVPN .ovpn, or ZIP bundle.'}</div>
          )}
        </div>

        <div className="vh__foot">
          <span className="vh__footic" data-on={killSwitch}>{killSwitch ? <Lock size={14} /> : <LockOpen size={14} />}</span>
          <span className="vh__footm">
            <b>{killSwitch ? 'Kill-switch active' : 'Kill-switch off'}</b>
            <span>{killSwitch ? 'egress fail-closed · host-wide' : 'traffic can use clearnet'}</span>
          </span>
        </div>
      </aside>

      <main className="vh__main">
        <header className="vh__dh">
          <span className="vh__dhic" data-accent={accent}>
            {selectedProfile ? <Server size={20} /> : <Shield size={20} />}
          </span>
          <span className="vh__dhm">
            <h1>{selectedProfile?.name ?? activeProfileName ?? 'Ripley VPN'}</h1>
            <span>
              {selectedProfile && (
                <>
                  <span className={`vh__chip ${activeProfileName === selectedProfile.name && connected ? 'ok' : 'mut'}`}>
                    {activeProfileName === selectedProfile.name && connected ? 'CONNECTED' : 'READY'}
                  </span>
                  <span className="vh__cc">{selectedMeta?.cc}</span>
                  <span className="vh__chip mut">{selectedProfile.kind === 'openvpn' ? 'OPENVPN' : 'WIREGUARD'}</span>
                  {selectedMeta?.region} · {selectedMeta?.endpoint}
                </>
              )}
              {!selectedProfile && 'Select or import a profile'}
            </span>
          </span>
          <span className="vh__dhacts">
            {tunnelActive
              ? <button className="vh__btn compact warn" onClick={() => setConfirm('disconnect-blocked')} disabled={busy}><Power size={11} />Disconnect</button>
              : <button className="vh__btn compact main" onClick={() => setConfirm('connect')} disabled={busy || !canConnect}><PlugZap size={11} />Connect</button>}
          </span>
        </header>

        <div className="vh__scrolld">
          <section className={`vh__conn ${accent}`}>
            <span className="vh__shield"><HeroIcon size={26} /></span>
            <span className="vh__connm">
              <span className="vh__connst">{phaseLabels[phase] ?? phase}</span>
              <span className="vh__connsub">
                {connected
                  ? `${String(status?.backend ?? 'WireGuard')} · interface ${String(status?.interface ?? 'unknown')}`
                  : blocked ? 'tunnel down · the kill-switch is holding egress' : 'no tunnel · direct network access is open'}
              </span>
            </span>
            <span className="vh__connwhen">
              <b>{connected ? age(status?.handshake_age_secs) : blocked ? '0 B' : 'OPEN'}</b>
              <span>{connected ? 'handshake' : blocked ? 'egress' : 'clearnet'}</span>
            </span>
          </section>

          <div className="vh__gates">
            <div className={`vh__gate ${blocked ? (connected ? 'ok' : 'warn') : 'danger'}`}>
              <span className="vh__gic">{blocked ? <GlobeLock size={16} /> : <Globe size={16} />}</span>
              <span className="vh__gm"><span className="k">Clearnet egress</span><span className="v">{blocked ? 'Blocked' : 'Open'}</span></span>
            </div>
            <div className={`vh__gate ${killSwitch ? 'ok' : 'danger'}`}>
              <span className="vh__gic">{killSwitch ? <Lock size={16} /> : <LockOpen size={16} />}</span>
              <span className="vh__gm"><span className="k">Kill-switch</span><span className="v">{killSwitch ? 'Active' : 'Off'}</span></span>
            </div>
          </div>

          {connected && (
            <div className="vh__metrics">
              <div><b className="ok">{age(status?.handshake_age_secs).replace(' ago', '')}</b><span>Last handshake</span></div>
              <div><b>{bytes(status?.received_bytes)}</b><span>Received</span></div>
              <div><b>{bytes(status?.sent_bytes)}</b><span>Sent</span></div>
            </div>
          )}

          <div className="vh__host">
            <AlertTriangle size={15} />
            <span><b>HOST-WIDE NETWORK CONTROL</b>WireGuard routes and the kill-switch apply to the whole computer, not just RipleyOS. Other apps and users are routed through the VPN, or blocked, until the tunnel is restored or clearnet is explicitly reopened.</span>
          </div>

          <section className="vh__conf">
            <div className="vh__confh">
              <FileKey2 size={12} />
              {selectedProfile ? `${selectedProfile.name}.${selectedProfile.kind === 'openvpn' ? 'ovpn' : 'conf'}` : 'profile preview'}
              {selectedProfile && (
                <button className="vh__ico" title="Copy redacted config" onClick={() => void navigator.clipboard.writeText(redactVpnProfileSecrets(configText))}>
                  <Copy size={12} />
                </button>
              )}
            </div>
            {selectedProfile?.kind === 'openvpn' ? (
              <div className="vh__unsupported">
                <b>OpenVPN profile loaded</b>
                <p>It is encrypted and inspectable, but the current broker only connects WireGuard. OpenVPN requires its own fail-closed broker state machine.</p>
              </div>
            ) : selectedProfile ? (
              <pre className="vh__confbody">{redactVpnProfileSecrets(configText)}</pre>
            ) : (
              <textarea
                value={configText}
                onChange={event => { setSelectedProfileId(null); setConfigText(event.target.value); }}
                rows={9}
                spellCheck={false}
                placeholder={'[Interface]\nPrivateKey = …\n[Peer]\nPublicKey = …'}
                className="vh__textarea"
              />
            )}
          </section>

          {selectedProfile && (
            <div className="vh__meta">
              <div className="r"><Waypoints size={13} /><span>Protocol</span><b>{selectedProfile.kind === 'openvpn' ? 'OpenVPN · preview' : 'WireGuard'}</b></div>
              <div className="r"><Server size={13} /><span>Endpoint</span><b>{selectedMeta?.endpoint}</b></div>
              <div className="r"><GlobeLock size={13} /><span>Allowed IPs</span><b>{configLine(configText, 'AllowedIPs')}</b></div>
            </div>
          )}

          {tunnelActive ? (
            <section className="vh__card">
              <div className="vh__sech"><Power size={12} />End this session</div>
              <div className="vh__btns">
                <button className="vh__btn session warn wide" onClick={() => setConfirm('disconnect-blocked')} disabled={busy}><Lock size={11} />Disconnect · stay blocked</button>
                <button className="vh__btn session danger wide" onClick={() => setConfirm('restore')} disabled={busy}><Globe size={11} />Disconnect · restore clearnet</button>
              </div>
              <p className="vh__p"><b>Stay blocked</b> drops the tunnel but keeps egress fail-closed. <b>Restore clearnet</b> reopens direct traffic and exposes this machine’s real IP.</p>
            </section>
          ) : (
            <section className="vh__card">
              <div className="vh__sech"><Shield size={12} />Recover</div>
              <div className="vh__btns">
                <button className="vh__btn recovery main wide" onClick={() => setConfirm('connect')} disabled={busy || !canConnect}><PlugZap size={11} />Connect {selectedProfile?.name ?? 'selected profile'}</button>
                {killSwitch
                  ? <button className="vh__btn recovery danger wide" onClick={() => setConfirm('disable-killswitch')} disabled={busy || !nativeControls}><LockOpen size={11} />Disable kill-switch</button>
                  : <button className="vh__btn recovery wide" onClick={() => setConfirm('recover')} disabled={busy || !nativeControls}><Lock size={11} />Re-arm blocked state</button>}
              </div>
              <p className="vh__p">{blocked ? 'Fail-closed is holding egress shut. Reconnect or explicitly restore clearnet.' : 'You are on clearnet. Connecting installs the host-wide block before the tunnel comes up.'}</p>
            </section>
          )}

          {cleanupRequired && (
            <button className="vh__emergency" onClick={() => setConfirm('emergency-restore')} disabled={busy || !window.api.vpnEmergencyRestore}>
              Emergency restore clearnet
            </button>
          )}
          {!nativeControls && <div className="vh__note">VPN mutations require the trusted native Tauri host.</div>}
          {notice && <div className="vh__note">{notice}</div>}
          {(statusError || error) && <div className="vh__error">{statusError || error}</div>}
        </div>
      </main>

      {confirm && <Confirm action={confirm} busy={busy} error={error} onCancel={() => !busy && setConfirm(null)} onConfirm={() => void run()} />}
    </div>
  );
}

function ProfileRow({ profile, latency, tested, selected, active, onPick, onRemove }: {
  profile: VpnProfile;
  latency?: number | null;
  tested: boolean;
  selected: boolean;
  active: boolean;
  onPick: () => void;
  onRemove: () => void;
}) {
  const meta = profileMeta(profile);
  const random = profile.name.toLowerCase() === 'xeovo-random';
  const flag = random ? null : countryFlag(meta.cc);
  return (
    <button type="button" className={`vh__row${selected ? ' is-on' : ''}`} onClick={onPick} title={profile.sourcePath}>
      <span className={`vh__ric${flag ? ' is-flag' : random ? ' is-random' : ''}`}>
        {random ? <Shuffle size={14} /> : flag ?? <Server size={14} />}
        {active && <span className="vh__st-dot" />}
      </span>
      <span className="vh__rm">
        <b><span className="vh__cc">{meta.cc}</span>{profile.name}</b>
        <span>{profile.kind === 'openvpn' ? 'OpenVPN · preview' : 'WireGuard'} · {meta.region}{active ? ' · live' : ''}</span>
      </span>
      {(random || tested) && (
        <span className="vh__latency">{random ? 'auto' : latency == null ? '—' : `${latency}ms`}</span>
      )}
      <span
        role="button"
        tabIndex={0}
        className="vh__del"
        title="Remove profile"
        onClick={event => { event.stopPropagation(); onRemove(); }}
        onKeyDown={event => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            event.stopPropagation();
            onRemove();
          }
        }}
      >
        <Trash2 size={12} />
      </span>
    </button>
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
    'disconnect-blocked': ['Disconnect and stay blocked?', 'This tears down WireGuard but keeps the host-wide egress block. Other apps remain offline until you restore clearnet or reconnect.'],
    restore: ['Restore clearnet?', 'This re-opens non-VPN networking for the whole computer after disconnecting the tunnel.'],
    'disable-killswitch': ['Disable kill-switch?', 'This removes the host-wide block. Traffic from any app may leave over clearnet if the VPN is not connected.'],
    recover: ['Recover blocked state?', 'The broker will reconcile the whole computer toward an offline, blocked state.'],
    'emergency-restore': ['Emergency restore clearnet?', 'BREAK GLASS: force teardown and remove the host-wide block despite dirty cleanup state. Other apps may immediately resume clearnet traffic.'],
  };
  const [title, body] = copy[action];
  return (
    <div className="vh__modal" role="dialog" aria-modal="true">
      <div className="vh__dialog">
        <div className="vh__dialogh">
          <h2>{title}</h2>
          <button onClick={onCancel} disabled={busy}><X size={15} /></button>
        </div>
        <p>{body}</p>
        {error && <div className="vh__error">{error}</div>}
        <div className="vh__dialogacts">
          <button className="vh__btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="vh__btn main" onClick={onConfirm} disabled={busy}>{busy ? 'Authorizing…' : 'Confirm'}</button>
        </div>
      </div>
    </div>
  );
}

export default VpnView;
