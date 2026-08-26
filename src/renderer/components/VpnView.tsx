import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, ArrowDownUp, CheckCircle2, Clock, Copy, FileCheck2, FileKey2, FilePlus2,
  FileX2, FolderArchive, FolderDown, Gauge, GitMerge, Globe, GlobeLock, Loader2, Lock,
  LockOpen, PanelLeftClose, PanelLeftOpen, PlugZap, Power, RefreshCw, Route, ScanSearch,
  Search, Server, Settings, Shield, ShieldAlert, ShieldCheck, ShieldOff, Shuffle,
  SlidersHorizontal, Trash2, Unplug, Waypoints, X,
} from 'lucide-react';
import {
  formatUptime, isRandomProfileName, isVirtualRandomProfile, parseConfLines, pickFastestPeer,
  profileBundleLabel, redactVpnProfileSecrets, stageVpnImport, withVirtualRandom,
  type ImportStage, type VpnProfile,
} from '../vpnProfiles';
import { createVpnTranslator } from '../vpnLocale';
import './VpnView.css';

type VpnStatus = Record<string, unknown>;
type ConfirmAction = 'connect' | 'reconnect' | 'disconnect-blocked' | 'restore' | 'disable-killswitch' | 'enable-killswitch' | 'disable-dns-filter' | 'enable-dns-filter' | 'recover' | 'emergency-restore' | null;
type Accent = 'ok' | 'warn' | 'danger';
/** Top-level host VPN screens from the redesign: Servers · Network controls · Import. */
type Screen = 'servers' | 'network' | 'import';

const regionByCode: Record<string, string> = {
  ae: 'UAE', al: 'Albania', at: 'Austria', au: 'Australia', be: 'Belgium', bg: 'Bulgaria',
  br: 'Brazil', ca: 'Canada', ch: 'Switzerland', cz: 'Czechia', de: 'Germany', dk: 'Denmark',
  ee: 'Estonia', es: 'Spain', fi: 'Finland', fr: 'France', gb: 'United Kingdom', gr: 'Greece',
  hk: 'Hong Kong', hr: 'Croatia', hu: 'Hungary', ie: 'Ireland', il: 'Israel', in: 'India',
  it: 'Italy', jp: 'Japan', kr: 'South Korea', lt: 'Lithuania', lu: 'Luxembourg', lv: 'Latvia',
  mx: 'Mexico', nl: 'Netherlands', no: 'Norway', nz: 'New Zealand', pl: 'Poland', pt: 'Portugal',
  ro: 'Romania', rs: 'Serbia', se: 'Sweden', sg: 'Singapore', sk: 'Slovakia', th: 'Thailand',
  tr: 'Turkey', tw: 'Taiwan', ua: 'Ukraine', uk: 'United Kingdom', us: 'United States',
};

/** Tokens that are never ISO country codes in profile names. */
const NAME_SKIP_TOKENS = new Set([
  'xeovo', 'tcp', 'udp', 'tls', 'wg', 'wireguard', 'openvpn', 'ovpn', 'vpn',
  'server', 'node', 'gw', 'gate', 'gateway', 'random', 'auto', 'fastest',
]);

function isRandomProfile(profile: VpnProfile | null | undefined): boolean {
  return !!profile && isRandomProfileName(profile.name);
}

/** Pull a 2-letter country code from names like `xeovo-fi`, `xeovo-us-nyc-tcp`. */
function countryCodeFromName(name: string): string {
  if (isRandomProfileName(name)) return '';
  const parts = name.toLowerCase().split(/[-_]+/).filter(Boolean);
  for (const part of parts) {
    if (NAME_SKIP_TOKENS.has(part)) continue;
    if (part === 'uk') return 'gb';
    if (regionByCode[part]) return part === 'uk' ? 'gb' : part;
    // Bare ISO-looking token even if region label is unknown.
    if (/^[a-z]{2}$/.test(part) && part !== 'ip') return part;
  }
  return '';
}

/** Resolve what actually connects: xeovo-random → fastest measured WireGuard peer. */
function resolveConnectTarget(
  profiles: VpnProfile[],
  selected: VpnProfile | null,
  latencies: Record<string, number | null>,
  t: (key: string, vars?: Record<string, string | number>) => string,
): { profile: VpnProfile; displayName: string; notice?: string } {
  if (!selected) throw new Error(t('selectConfig'));
  // OpenVPN relock (review round 1): the disk path is in, but the full
  // Model-A apply chain must land on both OSes before Connect is offered.
  // TODO(v1.1): remove this gate once the E2E matrix passes on Linux+macOS.
  if (selected.kind === 'openvpn') throw new Error(t('openvpnUnsupported'));
  if (!isRandomProfile(selected)) {
    return { profile: selected, displayName: selected.name };
  }
  const peers = profiles.filter(p => p.kind === 'wireguard' && !isRandomProfile(p));
  if (!peers.length) throw new Error(t('randomNeedsPeers'));
  const best = pickFastestPeer(profiles, latencies);
  if (!best) throw new Error(t('randomNeedsSpeeds'));
  return {
    profile: best,
    displayName: best.name,
    notice: t('randomPicked', { name: best.name }),
  };
}

function latencyTier(ms: number | null | undefined): 'fast' | 'mid' | 'slow' | 'none' {
  if (ms == null || !Number.isFinite(ms)) return 'none';
  if (ms <= 60) return 'fast';
  if (ms <= 140) return 'mid';
  return 'slow';
}

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

/** Pull host:port from a WireGuard/OpenVPN profile for speed probes. */
function extractEndpoint(configText: string): string | null {
  // WireGuard: Endpoint = host:port  (optional # comment)
  const wg = configText.match(/^\s*Endpoint\s*=\s*([^\r\n#]+)/im)?.[1]?.trim();
  if (wg) return wg;
  // OpenVPN: remote host [port]
  const ov = configText.match(/^\s*remote\s+(\S+)(?:\s+(\d+))?/im);
  if (ov) return ov[2] ? `${ov[1]}:${ov[2]}` : `${ov[1]}:1194`;
  return null;
}

function profileMeta(profile: VpnProfile): { cc: string; region: string; endpoint: string } {
  if (isRandomProfile(profile)) {
    return {
      cc: 'RND',
      region: 'Fastest available',
      endpoint: extractEndpoint(profile.configText) ?? 'auto',
    };
  }
  const code = countryCodeFromName(profile.name);
  const flagCode = code === 'uk' ? 'gb' : code;
  const endpoint = extractEndpoint(profile.configText) ?? 'endpoint in profile';
  return {
    cc: flagCode ? flagCode.toUpperCase() : profile.kind === 'openvpn' ? 'OV' : 'WG',
    region: regionByCode[code] ?? (code ? code.toUpperCase() : 'Imported profile'),
    endpoint,
  };
}

function configLine(text: string, key: string): string {
  // WireGuard keys are CamelCase without spaces (AllowedIPs, not "Allowed IPs").
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
  /** Present key = probe finished (number ms or null timeout). Absent = not probed yet. */
  const [latencies, setLatencies] = useState<Record<string, number | null>>({});
  /** Profile ids currently in an in-flight speed-test batch. */
  const [probingIds, setProbingIds] = useState<Set<string>>(() => new Set());
  const [sideCollapsed, setSideCollapsed] = useState(false);
  const [exitIp, setExitIp] = useState<string | null>(null);
  const [exitIpBusy, setExitIpBusy] = useState(false);
  const [exitIpErr, setExitIpErr] = useState('');
  /**
   * Host-backed session clock only:
   * - `sessionStartedAt`: unix seconds from status.connected_at_unix (or a true
   *   offline→online connect observed in this window — never window-open time)
   * - `uptimeAnchor`: status.uptime_secs pinned to wall clock between polls
   */
  const [sessionStartedAt, setSessionStartedAt] = useState<number | null>(null);
  const [uptimeAnchor, setUptimeAnchor] = useState<{ wallMs: number; uptimeSecs: number } | null>(null);
  const wasTunnelLive = useRef(false);
  const [tick, setTick] = useState(0);
  const [screen, setScreen] = useState<Screen>('servers');
  const [stage, setStage] = useState<ImportStage | null>(null);
  const [stageBusy, setStageBusy] = useState(false);
  const [importDropHot, setImportDropHot] = useState(false);
  const configFile = useRef<HTMLInputElement | null>(null);
  const zipFile = useRef<HTMLInputElement | null>(null);
  const looseFile = useRef<HTMLInputElement | null>(null);
  const nativeControls = Boolean(
    window.api.vpnConnect && window.api.vpnDisconnect &&
    window.api.vpnSetKillswitch && window.api.vpnRecover && window.api.vpnSetDnsFilter,
  );
  /** Stored profiles + optional virtual xeovo-random pin (never persisted). */
  const displayProfiles = useMemo(() => withVirtualRandom(profiles), [profiles]);

  const refresh = useCallback(async () => {
    if (!window.api.vpnStatus) {
      setStatusError(t('mutationsRequired'));
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
  }, [refresh, t]);

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
      .catch(e => setError(t('storedProfilesError', { error: String(e) })));
  }, []);

  const persistProfiles = async (nextProfiles: VpnProfile[], nextSelectedId: string | null) => {
    if (!window.api.vpnProfilesSave) {
      setProfilesPersisted(false);
      throw new Error(t('mutationsRequired'));
    }
    // Never write the synthetic random pin into encrypted storage.
    const durable = nextProfiles.filter(p => !isVirtualRandomProfile(p));
    const selectedDurable = nextSelectedId && durable.some(p => p.id === nextSelectedId)
      ? nextSelectedId
      : durable[0]?.id ?? null;
    await window.api.vpnProfilesSave({ v: 1, profiles: durable, selectedProfileId: selectedDurable });
    setProfilesPersisted(true);
  };

  const phase = String(status?.phase ?? 'unknown');
  const egress = String(status?.egress ?? 'unknown');
  const connected = phase === 'connected';
  const tunnelActive = typeof status?.interface === 'string' && status.interface.length > 0;
  const blocked = egress === 'blocked';
  const killSwitch = status?.killswitch_active === true;
  const dnsFilter = status?.dns_filter === true;
  const cleanupRequired = status?.cleanup_required === true;
  const activeProfileName = typeof status?.profile_name === 'string' && status.profile_name.trim()
    ? status.profile_name.trim()
    : null;

  // Auto-retry: if the tunnel drops on its own (a connected state unexpectedly
  // becomes disconnected/errored with no user action), reconnect once using the
  // last-used profile. The persistent helper + cached endpoint IP make this
  // prompt-free and DNS-free. Only retries after a real drop, never while the
  // user is actively connecting/disconnecting.
  const autoRetried = useRef(false);
  const wasConnected = useRef(false);
  const lastUsedConfig = useRef<string | null>(null);
  useEffect(() => {
    if (busy) {
      wasConnected.current = phase === 'connected';
      return;
    }
    if (phase === 'connected') {
      wasConnected.current = true;
      autoRetried.current = false;
      return;
    }
    const dropped = wasConnected.current
      && (phase === 'disconnected_blocked' || phase === 'error_blocked')
      && lastUsedConfig.current
      && !autoRetried.current;
    if (!dropped) return;
    wasConnected.current = false;
    autoRetried.current = true;
    const config = lastUsedConfig.current;
    (async () => {
      setBusy(true);
      try {
        if (!window.api.vpnConnect) throw new Error(t('mutationsRequired'));
        // dropped above guarantees config is set; profile name is optional.
        await window.api.vpnConnect(config!, activeProfileName ?? undefined);
        setError('');
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(false);
        void refresh();
      }
    })();
  }, [phase, busy, activeProfileName, t]);
  const selectedProfile = displayProfiles.find(profile => profile.id === selectedProfileId) ?? null;
  const selectedMeta = selectedProfile && !isVirtualRandomProfile(selectedProfile) ? profileMeta(selectedProfile) : selectedProfile
    ? { cc: 'RND', region: t('virtualRandomHint'), endpoint: 'auto' }
    : null;
  const accent: Accent = connected ? 'ok' : blocked ? 'warn' : 'danger';
  const HeroIcon = connected ? ShieldCheck : blocked ? ShieldAlert : ShieldOff;
  const tunnelLive = connected || tunnelActive;

  // Uptime must come from the host (or a connect we observed), never from
  // "window just opened onto an already-live tunnel".
  useEffect(() => {
    if (!tunnelLive) {
      wasTunnelLive.current = false;
      setSessionStartedAt(null);
      setUptimeAnchor(null);
      return;
    }

    const hostStart =
      typeof status?.connected_at_unix === 'number' && Number.isFinite(status.connected_at_unix)
        ? Math.floor(status.connected_at_unix as number)
        : null;
    const hostUptime =
      typeof status?.uptime_secs === 'number' && Number.isFinite(status.uptime_secs)
        ? Math.max(0, Math.floor(status.uptime_secs as number))
        : null;

    if (hostStart != null) {
      setSessionStartedAt(hostStart);
      setUptimeAnchor(null);
    } else if (hostUptime != null) {
      // Advance between 5s status polls without resetting on remount.
      setUptimeAnchor({ wallMs: Date.now(), uptimeSecs: hostUptime });
      setSessionStartedAt(null);
    } else if (!wasTunnelLive.current) {
      // True offline→online transition in this window (user just connected here).
      setSessionStartedAt(Math.floor(Date.now() / 1000));
      setUptimeAnchor(null);
    }
    // else: already live when the view mounted and host sent no clock → stay "—"
    wasTunnelLive.current = true;
  }, [tunnelLive, status?.connected_at_unix, status?.uptime_secs]);

  useEffect(() => {
    if (!tunnelLive) return;
    const id = window.setInterval(() => setTick(n => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [tunnelLive]);

  const liveUptime = useMemo(() => {
    void tick;
    if (!tunnelLive) return null;
    if (sessionStartedAt != null) {
      return formatUptime(Math.max(0, Math.floor(Date.now() / 1000) - sessionStartedAt));
    }
    if (uptimeAnchor) {
      const extra = Math.floor((Date.now() - uptimeAnchor.wallMs) / 1000);
      return formatUptime(Math.max(0, uptimeAnchor.uptimeSecs + extra));
    }
    return null;
  }, [tick, tunnelLive, sessionStartedAt, uptimeAnchor]);

  const probeExitIp = useCallback(async () => {
    if (!window.api.vpnProbeExitIp) {
      setExitIpErr(t('exitIpUnavailable'));
      return;
    }
    // Fail-closed offline: nothing should leave — don't pretend to check.
    if (blocked && !connected && !tunnelActive) {
      setExitIp(null);
      setExitIpErr(t('exitIpBlockedHint'));
      return;
    }
    setExitIpBusy(true);
    setExitIpErr('');
    try {
      const result = await window.api.vpnProbeExitIp();
      if (!result?.ip) throw new Error(t('exitIpUnknown'));
      setExitIp(result.ip);
    } catch (e) {
      setExitIp(null);
      const msg = e instanceof Error
        ? e.message
        : (e && typeof e === 'object' && 'message' in e && typeof (e as { message: unknown }).message === 'string')
          ? (e as { message: string }).message
          : String(e);
      setExitIpErr(t('exitIpError', { error: msg }));
    } finally {
      setExitIpBusy(false);
    }
  }, [blocked, connected, tunnelActive, t]);

  useEffect(() => {
    if (blocked && !connected && !tunnelActive) {
      setExitIp(null);
      return;
    }
    // Auto-check once when we land on a routable state (clearnet open or tunnel up).
    if (!window.api.vpnProbeExitIp) return;
    void probeExitIp();
    // Only re-run when connectivity class changes — not on every probeExitIp identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, blocked, connected, tunnelActive]);

  const filteredProfiles = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return displayProfiles;
    return displayProfiles.filter(profile => {
      const meta = isVirtualRandomProfile(profile)
        ? { region: 'random', cc: 'RND' }
        : profileMeta(profile);
      return [profile.name, profile.kind, meta.region, meta.cc].some(value => value.toLowerCase().includes(query));
    });
  }, [filter, displayProfiles]);
  const speedSorted = useCallback((items: VpnProfile[]) => {
    if (!sortFastest) return items;
    return [...items].sort((a, b) => {
      if (isRandomProfile(a)) return -1;
      if (isRandomProfile(b)) return 1;
      // Unprobed sink below timeouts; measured first.
      const la = Object.prototype.hasOwnProperty.call(latencies, a.id)
        ? (latencies[a.id] ?? Number.POSITIVE_INFINITY - 1)
        : Number.POSITIVE_INFINITY;
      const lb = Object.prototype.hasOwnProperty.call(latencies, b.id)
        ? (latencies[b.id] ?? Number.POSITIVE_INFINITY - 1)
        : Number.POSITIVE_INFINITY;
      return la - lb;
    });
  }, [latencies, sortFastest]);
  const pinnedProfiles = speedSorted(filteredProfiles.filter(profile => isRandomProfile(profile)));
  /** Non-pinned profiles grouped by import bundle (each ZIP is its own section). */
  const bundleGroups = useMemo(() => {
    const others = filteredProfiles.filter(profile => !isRandomProfile(profile));
    const order: string[] = [];
    const map = new Map<string, VpnProfile[]>();
    for (const profile of others) {
      const label = profileBundleLabel(profile);
      if (!map.has(label)) {
        map.set(label, []);
        order.push(label);
      }
      map.get(label)!.push(profile);
    }
    return order.map(label => ({
      label,
      profiles: speedSorted(map.get(label) ?? []),
    }));
  }, [filteredProfiles, speedSorted]);

  const testSpeeds = async () => {
    if (speedTesting) return;
    // Always include the live peer (never skip the connected server).
    const liveName = connected && activeProfileName ? activeProfileName : null;
    const liveEndpoint =
      typeof status?.endpoint === 'string' && status.endpoint.trim()
        ? status.endpoint.trim()
        : null;
    const candidates = profiles
      .filter(profile => profile.kind === 'wireguard' && !isVirtualRandomProfile(profile))
      .sort((a, b) => {
        // Probe the connected profile first so it never sits at the end of a long queue.
        if (liveName && a.name === liveName) return -1;
        if (liveName && b.name === liveName) return 1;
        return 0;
      });
    if (!candidates.length) return;
    if (!window.api.vpnProbeEndpoints) {
      setError(t('speedHostError'));
      return;
    }
    setSpeedTesting(true);
    setError('');
    // Clear prior samples only — do NOT pre-fill null (that showed "timeout" before probing).
    const next: Record<string, number | null> = {};
    setLatencies({});
    setProbingIds(new Set());
    try {
      // Probe in small batches so the UI fills in as results arrive.
      const BATCH = 6;
      for (let i = 0; i < candidates.length; i += BATCH) {
        const batch = candidates.slice(i, i + BATCH);
        setProbingIds(new Set(batch.map(p => p.id)));
        // Prefer the host-pinned peer IP for the live profile — config hostnames
        // can resolve differently under tunnel DNS and miss the kill-switch hole.
        const endpoints = batch.map(profile => (
          liveName && liveEndpoint && profile.name === liveName
            ? liveEndpoint
            : profileMeta(profile).endpoint
        ));
        const measured = await window.api.vpnProbeEndpoints!(endpoints);
        batch.forEach((profile, index) => {
          next[profile.id] = measured[index] ?? null;
        });
        setLatencies({ ...next });
      }
      setSpeedTestedAt(Date.now());
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(t('speedError', { error: msg }));
    } finally {
      setProbingIds(new Set());
      setSpeedTesting(false);
    }
  };

  const selectProfile = (profile: VpnProfile) => {
    setSelectedProfileId(profile.id);
    setConfigText(profile.configText);
    setError('');
    if (isVirtualRandomProfile(profile)) return; // virtual pin is not durable selection
    void persistProfiles(profiles, profile.id)
      .catch(err => setError(t('removeError', { name: selectedProfile?.name ?? '', error: String(err) })));
  };

  /** Settings gear: show Network / Import panels in the rail (not always-on chrome). */
  const [settingsOpen, setSettingsOpen] = useState(false);

  const goServers = () => {
    setScreen('servers');
    setSettingsOpen(false);
    setStage(null);
    setImportDropHot(false);
    setStageBusy(false);
  };

  const goNetwork = () => {
    setScreen('network');
    setSettingsOpen(true);
    setStage(null);
    setImportDropHot(false);
  };

  const openImport = () => {
    setScreen('import');
    setSettingsOpen(true);
    setStage(null);
    setError('');
    setNotice('');
  };

  const closeImport = () => {
    goServers();
  };

  const toggleSettings = () => {
    if (settingsOpen) {
      goServers();
      return;
    }
    // Open settings into Network controls (the host-wide panel), not a dead menu.
    goNetwork();
  };

  const stageFiles = async (fileList: FileList | File[] | null | undefined) => {
    const files = Array.isArray(fileList)
      ? fileList
      : fileList
        ? Array.from(fileList)
        : [];
    if (!files.length) {
      setError(t('importNoFiles'));
      return;
    }
    setStageBusy(true);
    setError('');
    setNotice('');
    try {
      const next = await stageVpnImport(files, profiles.map(p => p.name));
      // Merge into an existing stage when the user keeps adding files.
      setStage(prev => {
        if (!prev) return next;
        const names = new Set([
          ...profiles.map(p => p.name.toLowerCase()),
          ...prev.additions.map(p => p.name.toLowerCase()),
        ]);
        const mergedAdds = [...prev.additions];
        for (const p of next.additions) {
          if (names.has(p.name.toLowerCase())) {
            next.duplicates.push(p.name);
            continue;
          }
          names.add(p.name.toLowerCase());
          mergedAdds.push({ ...p, id: `import:${mergedAdds.length}:${p.sourcePath}` });
        }
        return {
          additions: mergedAdds,
          duplicates: [...prev.duplicates, ...next.duplicates],
          rejected: [...prev.rejected, ...next.rejected],
          sources: [...prev.sources, ...next.sources],
        };
      });
      if (!next.additions.length && !next.duplicates.length && !next.rejected.length) {
        setError(t('importEmptyResult'));
      } else if (!next.additions.length && next.rejected.length) {
        setError(next.rejected.map(r => `${r.name}: ${r.reason}`).join(' · '));
      } else if (!next.additions.length && next.duplicates.length) {
        setNotice(t('noProfilesAdded'));
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setStageBusy(false);
    }
  };

  /** Confirm staged additions — merge only, never overwrite existing names. */
  const commitImport = async () => {
    if (!stage?.additions.length) return;
    setBusy(true);
    setError('');
    try {
      const next = [...profiles, ...stage.additions];
      const nextSelected = stage.additions[0];
      await persistProfiles(next, nextSelected.id);
      setProfiles(next);
      setSelectedProfileId(nextSelected.id);
      setConfigText(nextSelected.configText);
      setNotice(t('imported', {
        count: stage.additions.length,
        plural: stage.additions.length === 1 ? '' : 's',
      }));
      closeImport();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const removeProfile = async (profile: VpnProfile) => {
    if (isVirtualRandomProfile(profile)) return; // cannot remove the synthetic pin
    if (tunnelActive && activeProfileName === profile.name) {
      setError(t('disconnectBeforeRemove'));
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
      setNotice(t('removed', { name: profile.name }));
      setError('');
    } catch (e) {
      setError(t('removeError', { name: profile.name, error: String(e) }));
    }
  };

  const run = async () => {
    const action = confirm;
    if (!action) return;
    setBusy(true);
    setError('');
    try {
      if (action === 'connect' || action === 'reconnect') {
        if (!window.api.vpnConnect) throw new Error(t('mutationsRequired'));
        const target = resolveConnectTarget(profiles, selectedProfile, latencies, t);
        if (!target.profile.configText.trim()) throw new Error(t('selectConfig'));
        // Broker refuses "up" while configured — reconnect stays fail-closed first.
        if (action === 'reconnect' || tunnelActive) {
          if (!window.api.vpnDisconnect) throw new Error(t('mutationsRequired'));
          await window.api.vpnDisconnect(false);
        }
        await window.api.vpnConnect(target.profile.configText, target.displayName);
        // Remember the config for prompt-free auto-retry if the tunnel drops.
        lastUsedConfig.current = target.profile.configText;
        // Now that DNS works through the tunnel, pre-resolve every profile's
        // endpoint IP so a later reconnect to ANY node (kill-switch armed) can
        // skip DNS — even on networks where the DoH window is ISP-blocked.
        try {
          const wgConfigs = profiles
            .filter(p => p.kind === 'wireguard' && !isVirtualRandomProfile(p) && p.configText.trim())
            .map(p => p.configText);
          if (wgConfigs.length && window.api.vpnCacheEndpoints) {
            void window.api.vpnCacheEndpoints(wgConfigs);
          }
        } catch { /* cache is best-effort; connect already succeeded */ }
        if (target.notice) setNotice(target.notice);
        // Keep selection on random when user chose it; status still shows real peer.
        if (!isRandomProfile(selectedProfile)) {
          setSelectedProfileId(target.profile.id);
          setConfigText(target.profile.configText);
        }
      } else if (action === 'disconnect-blocked') {
        if (!window.api.vpnDisconnect) throw new Error(t('mutationsRequired'));
        await window.api.vpnDisconnect(false);
        // User-initiated stop — no auto-retry.
        lastUsedConfig.current = null;
      } else if (action === 'restore') {
        if (!window.api.vpnDisconnect) throw new Error(t('mutationsRequired'));
        await window.api.vpnDisconnect(true);
        lastUsedConfig.current = null;
      } else if (action === 'disable-killswitch') {
        if (!window.api.vpnSetKillswitch) throw new Error(t('mutationsRequired'));
        await window.api.vpnSetKillswitch(false);
      } else if (action === 'enable-killswitch') {
        if (!window.api.vpnSetKillswitch) throw new Error(t('mutationsRequired'));
        await window.api.vpnSetKillswitch(true);
      } else if (action === 'disable-dns-filter') {
        if (!window.api.vpnSetDnsFilter) throw new Error(t('mutationsRequired'));
        await window.api.vpnSetDnsFilter(false);
      } else if (action === 'enable-dns-filter') {
        if (!window.api.vpnSetDnsFilter) throw new Error(t('mutationsRequired'));
        await window.api.vpnSetDnsFilter(true);
      } else if (action === 'recover') {
        if (!window.api.vpnRecover) throw new Error(t('mutationsRequired'));
        await window.api.vpnRecover();
      } else if (action === 'emergency-restore') {
        if (!window.api.vpnEmergencyRestore) throw new Error(t('emergencyUnavailable'));
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

  const canConnect = nativeControls && !!selectedProfile && selectedProfile.kind !== 'openvpn'
    && (isRandomProfile(selectedProfile) || !!configText.trim());
  const isEmpty = profiles.length === 0;
  const confLines = useMemo(
    () => (selectedProfile && !isVirtualRandomProfile(selectedProfile) && selectedProfile.kind !== 'openvpn'
      ? parseConfLines(configText)
      : []),
    [selectedProfile, configText],
  );

  const activeConfigText = activeProfileName
    ? (profiles.find(p => p.name === activeProfileName)?.configText ?? configText)
    : configText;
  const policyDns = configLine(activeConfigText, 'DNS');
  const policyAllowed = configLine(activeConfigText, 'AllowedIPs');
  const statusSub = activeProfileName
    ? `${activeProfileName}${status?.interface ? ` · ${String(status.interface)}` : ''}`
    : blocked ? t('noTunnelNothing') : t('noTunnelDirect');

  const navItems: { id: Screen; label: string; sub: string; icon: React.ReactNode }[] = [
    { id: 'servers', label: t('navServers'), sub: t('navServersSub', { count: profiles.length }), icon: <Server size={14} /> },
    { id: 'network', label: t('navNetwork'), sub: t('navNetworkSub'), icon: <SlidersHorizontal size={14} /> },
    { id: 'import', label: t('navImport'), sub: t('navImportSub'), icon: <FolderDown size={14} /> },
  ];

  return (
    <div className={`vh vh--${accent}${sideCollapsed ? ' is-rail' : ''}${settingsOpen ? ' is-nav' : ''}`}>
      <aside className="vh__side">
        <div className="vh__stat">
          <span className="vh__statmk" data-accent={accent}>
            {connected ? <ShieldCheck size={16} /> : blocked ? <ShieldAlert size={16} /> : <ShieldOff size={16} />}
          </span>
          <span className="vh__statm">
            <b><span className={`vh__dot ${accent}`} />{connected ? t('connected') : blocked ? t('blocked') : t('clearnet')}</b>
            <span>{statusSub}</span>
          </span>
          <span className="vh__statacts">
            <button
              className={`vh__ico vh__gear${settingsOpen ? ' is-on' : ''}`}
              onClick={toggleSettings}
              title={settingsOpen ? t('settingsClose') : t('settingsOpen')}
              aria-pressed={settingsOpen}
            >
              <Settings size={13} />
            </button>
            <button className="vh__ico vh__railbtn" onClick={() => setSideCollapsed(value => !value)} title={sideCollapsed ? t('expandSidebar') : t('collapseSidebar')}>
              {sideCollapsed ? <PanelLeftOpen size={14} /> : <PanelLeftClose size={14} />}
            </button>
          </span>
        </div>

        {/* Hidden inputs always mounted so Import can open files from any screen.
            Snapshot File[] BEFORE clearing value — FileList is live and becomes empty on reset. */}
        <input
          ref={configFile}
          type="file"
          accept=".conf,.ovpn,.zip,text/plain,application/zip"
          multiple
          className="vh__file"
          onChange={event => {
            const input = event.currentTarget;
            const files = Array.from(input.files ?? []);
            input.value = '';
            if (!files.length) return;
            // Ensure the Import screen is visible without wiping a just-built stage:
            // set screen/settings first, then stage (openImport would clear stage).
            setScreen('import');
            setSettingsOpen(true);
            setError('');
            setNotice('');
            void stageFiles(files);
          }}
        />
        <input
          ref={zipFile}
          type="file"
          accept=".zip,application/zip"
          className="vh__file"
          onChange={event => {
            const input = event.currentTarget;
            const files = Array.from(input.files ?? []);
            input.value = '';
            if (!files.length) return;
            setScreen('import');
            setSettingsOpen(true);
            setError('');
            setNotice('');
            void stageFiles(files);
          }}
        />
        <input
          ref={looseFile}
          type="file"
          accept=".conf,.ovpn,text/plain"
          multiple
          className="vh__file"
          onChange={event => {
            const input = event.currentTarget;
            const files = Array.from(input.files ?? []);
            input.value = '';
            if (!files.length) return;
            setScreen('import');
            setSettingsOpen(true);
            setError('');
            setNotice('');
            void stageFiles(files);
          }}
        />

        {settingsOpen ? (
          <div className="vh__nav">
            <div className="vh__sec">{t('navSettings')}</div>
            {navItems.map(item => (
              <button
                key={item.id}
                type="button"
                className={`vh__navrow${screen === item.id ? ' is-on' : ''}`}
                onClick={() => {
                  if (item.id === 'servers') goServers();
                  else if (item.id === 'network') goNetwork();
                  else openImport();
                }}
              >
                <span className="vh__ric">{item.icon}</span>
                <span className="vh__rm"><b>{item.label}</b><span>{item.sub}</span></span>
              </button>
            ))}
          </div>
        ) : (
          <>
            <div className="vh__tools">
              <label className="vh__find">
                <Search size={12} />
                <input value={filter} onChange={event => setFilter(event.target.value)} placeholder={t('filterServers')} spellCheck={false} />
              </label>
              <button className="vh__ico" title={t('importOpen')} onClick={openImport}>
                <FolderDown size={14} />
              </button>
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
              {pinnedProfiles.length > 0 && <div className="vh__sec">{t('pinned')} · {pinnedProfiles.length}</div>}
              {pinnedProfiles.map(profile => (
                <ProfileRow key={profile.id} profile={profile} latency={latencies[profile.id]} probed={Object.prototype.hasOwnProperty.call(latencies, profile.id)} probing={probingIds.has(profile.id)} runActive={speedTesting} selected={profile.id === selectedProfileId} active={connected && profile.name === activeProfileName} onPick={() => selectProfile(profile)} onRemove={() => void removeProfile(profile)} t={t} />
              ))}
              {bundleGroups.map(group => (
                <React.Fragment key={group.label}>
                  <div className="vh__sec">{group.label} · {group.profiles.length}</div>
                  {group.profiles.map(profile => (
                    <ProfileRow key={profile.id} profile={profile} latency={latencies[profile.id]} probed={Object.prototype.hasOwnProperty.call(latencies, profile.id)} probing={probingIds.has(profile.id)} runActive={speedTesting} selected={profile.id === selectedProfileId} active={connected && profile.name === activeProfileName} onPick={() => selectProfile(profile)} onRemove={() => void removeProfile(profile)} t={t} />
                  ))}
                </React.Fragment>
              ))}
              {!filteredProfiles.length && (
                <div className="vh__empty">{profiles.length ? t('noMatching') : t('importProfilesHint')}</div>
              )}
            </div>
          </>
        )}

        <div className="vh__foot">
          <span className="vh__footic" data-on={killSwitch}>{killSwitch ? <Lock size={14} /> : <LockOpen size={14} />}</span>
          <span className="vh__footm">
            <b>{killSwitch ? t('killActive') : t('killOff')}</b>
            <span>{killSwitch ? t('failClosedHost') : t('clearnetTraffic')}</span>
          </span>
        </div>
      </aside>

      <main className="vh__main">
        {screen === 'network' ? (
          <>
            <header className="vh__dh">
              <span className="vh__dhic" data-accent={accent}><SlidersHorizontal size={20} /></span>
              <span className="vh__dhm">
                <h1>{t('networkTitle')}</h1>
                <span>{t('networkSub')}</span>
              </span>
            </header>
            <div className="vh__scrolld">
              <div className="vh__host">
                <AlertTriangle size={15} />
                <span><b>{t('hostWideTitle')}</b>{t('hostWideBody')}</span>
              </div>

              <section className={`vh__card vh__ks${killSwitch ? ' is-on' : ''}`}>
                <div className="vh__sech">
                  <Lock size={12} />{t('killSwitch')}
                  <em className={killSwitch ? 'ok' : 'off'}>{killSwitch ? t('stateOn') : t('stateOff')}</em>
                </div>
                <button
                  type="button"
                  className={`vh__kstoggle${killSwitch ? ' is-on' : ''}`}
                  disabled={busy || !nativeControls || (tunnelActive && killSwitch)}
                  title={tunnelActive && killSwitch ? t('ksToggleConnectedHint') : undefined}
                  onClick={() => {
                    if (killSwitch) {
                      if (tunnelActive) {
                        setError(t('ksToggleConnectedHint'));
                        return;
                      }
                      setConfirm('disable-killswitch');
                    } else {
                      setConfirm('enable-killswitch');
                    }
                  }}
                >
                  <span className="vh__kstoggleic">{killSwitch ? <ShieldCheck size={16} /> : <ShieldOff size={16} />}</span>
                  <span className="vh__kstogglem">
                    <span className="k">{t('ksFailClosed')}</span>
                    <span className="v">{t('ksBlockEverything')}</span>
                  </span>
                  <span className={`vh__switch${killSwitch ? ' is-on' : ''}`} aria-hidden />
                </button>
                <p className="vh__p">{t('ksExplain')}</p>
              </section>

              <section className={`vh__card vh__ks${dnsFilter ? ' is-on' : ''}`}>
                <div className="vh__sech">
                  <span className="vh__sechk"><span>DNS</span></span>
                  <div className="vh__sechh"><b>{t('dnsFilterTitle')}</b><span>{t('dnsFilterSub')}</span></div>
                </div>
                <button
                  type="button"
                  className={`vh__kstoggle${dnsFilter ? ' is-on' : ''}`}
                  disabled={busy || !nativeControls}
                  onClick={() => setConfirm(dnsFilter ? 'disable-dns-filter' : 'enable-dns-filter')}
                >
                  <span className="vh__kstoggleic">{dnsFilter ? <ShieldCheck size={16} /> : <Globe size={16} />}</span>
                  <span className="vh__kstogglem">
                    <span className="k">{t('dnsFilterLabel')}</span>
                    <span className="v">{t('dnsFilterValue', { state: dnsFilter ? 'on' : 'off' })}</span>
                  </span>
                  <span className={`vh__switch${dnsFilter ? ' is-on' : ''}`} aria-hidden />
                </button>
                <p className="vh__p">{t('dnsFilterExplain')}</p>
              </section>

              <section className="vh__card">
                <div className="vh__sech"><Route size={12} />{t('egressPolicy')}</div>
                <div className="vh__policy">
                  <div className="vh__policyrow">
                    <span className="k"><Waypoints size={13} />{t('policyMode')}</span>
                    <b>{policyAllowed !== '—' ? t('policyRouteAll', { cidrs: policyAllowed }) : t('policyRouteAllDefault')}</b>
                  </div>
                  <div className="vh__policyrow">
                    <span className="k"><Globe size={13} />{t('policyDns')}</span>
                    <b>{policyDns !== '—' ? t('policyDnsInTunnel', { dns: policyDns }) : t('policyDnsUnknown')}</b>
                  </div>
                  <div className="vh__policyrow">
                    <span className="k"><Unplug size={13} />{t('policyOnDrop')}</span>
                    <b className={killSwitch ? 'ok' : 'warn'}>{killSwitch ? t('policyBlockFailClosed') : t('policyOpenClearnet')}</b>
                  </div>
                </div>
              </section>

              <section className="vh__danger">
                <div className="vh__sech"><AlertTriangle size={12} />{t('dangerZone')}</div>
                <div className="vh__dangercard">
                  <span className="vh__dangeric"><LockOpen size={18} /></span>
                  <span className="vh__dangerm">
                    <b>{t('disableKill')}</b>
                    <span>{t('dangerDisableBody')}</span>
                  </span>
                  <button
                    className="vh__btn danger"
                    disabled={busy || !nativeControls || !killSwitch || tunnelActive}
                    onClick={() => setConfirm('disable-killswitch')}
                    title={tunnelActive ? t('ksToggleConnectedHint') : undefined}
                  >
                    <LockOpen size={12} />{t('disable')}
                  </button>
                </div>
                {tunnelActive && (
                  <div className="vh__btns" style={{ marginTop: 10 }}>
                    <button className="vh__btn session warn wide" onClick={() => setConfirm('disconnect-blocked')} disabled={busy}>
                      <Lock size={11} />{t('stayBlocked')}
                    </button>
                    <button className="vh__btn session danger wide" onClick={() => setConfirm('restore')} disabled={busy}>
                      <Globe size={11} />{t('restoreClearnet')}
                    </button>
                  </div>
                )}
                {cleanupRequired && (
                  <button className="vh__emergency" style={{ marginTop: 10 }} onClick={() => setConfirm('emergency-restore')} disabled={busy || !window.api.vpnEmergencyRestore}>
                    {t('emergency')}
                  </button>
                )}
              </section>

              {(error || statusError) && <div className="vh__error">{error || statusError}</div>}
              {notice && <div className="vh__note">{notice}</div>}
            </div>
          </>
        ) : screen === 'import' ? (
          <>
            <header className="vh__dh">
              <span className="vh__dhic" data-accent="ok"><FolderDown size={20} /></span>
              <span className="vh__dhm">
                <h1>{t('importScreenTitle')}</h1>
                <span>{t('importScreenSub')}</span>
              </span>
              <span className="vh__dhacts">
                <button className="vh__btn compact" onClick={closeImport} disabled={busy}>{t('importCancel')}</button>
                <button
                  className="vh__btn compact main"
                  onClick={() => void commitImport()}
                  disabled={busy || stageBusy || !stage?.additions.length}
                >
                  <FolderDown size={11} />
                  {t('importAddN', {
                    count: stage?.additions.length ?? 0,
                    plural: (stage?.additions.length ?? 0) === 1 ? '' : 's',
                  })}
                </button>
              </span>
            </header>
            <div className="vh__scrolld">
              <div
                className={`vh__drop vh__drop--import${importDropHot ? ' is-hot' : ''}`}
                onDragOver={event => { event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; setImportDropHot(true); }}
                onDragLeave={() => setImportDropHot(false)}
                onDrop={event => {
                  event.preventDefault();
                  setImportDropHot(false);
                  const files = Array.from(event.dataTransfer.files ?? []);
                  if (files.length) void stageFiles(files);
                }}
              >
                <FolderArchive size={22} />
                <b>{t('importDropTitle')}</b>
                <span>{t('importDropBody')}</span>
                {stage?.sources.length ? (
                  <span className="vh__dropsrc">{t('importSources', { list: stage.sources.join(' · ') })}</span>
                ) : null}
                <div className="vh__dropacts">
                  <button type="button" className="vh__btn" onClick={() => zipFile.current?.click()} disabled={stageBusy}>
                    <FolderArchive size={12} />{t('importChooseZip')}
                  </button>
                  <button type="button" className="vh__btn" onClick={() => looseFile.current?.click()} disabled={stageBusy}>
                    <FilePlus2 size={12} />{t('importChooseLoose')}
                  </button>
                </div>
                {stageBusy && <span className="vh__stagebusy"><Loader2 size={12} className="vh__spin" />{t('importStaging')}</span>}
              </div>

              <section className="vh__card vh__importsec">
                <div className="vh__sech"><GitMerge size={12} />{t('importMergeTitle')}<em>{t('importMergeNothing')}</em></div>
                <p className="vh__p">{t('importMergeBody', {
                  count: profiles.length,
                  plural: profiles.length === 1 ? '' : 's',
                })}</p>
              </section>

              <section className="vh__card vh__importsec">
                <div className="vh__sech"><ScanSearch size={12} />{t('importValidationTitle')}<em>{t('importValidationSub')}</em></div>
                <div className="vh__checks">
                  <div className="vh__check"><CheckCircle2 size={15} /><span><b>{t('importCheckPaths')}</b><i>{t('importCheckPathsSub')}</i></span></div>
                  <div className="vh__check"><CheckCircle2 size={15} /><span><b>{t('importCheckSize')}</b><i>{t('importCheckSizeSub')}</i></span></div>
                  <div className="vh__check"><CheckCircle2 size={15} /><span><b>{t('importCheckSecrets')}</b><i>{t('importCheckSecretsSub')}</i></span></div>
                </div>
              </section>

              {stage && (stage.additions.length > 0 || stage.rejected.length > 0 || stage.duplicates.length > 0) ? (
                <section className="vh__card vh__importsec">
                  {stage.additions.length > 0 && (
                    <>
                      <div className="vh__sech"><FileCheck2 size={12} />{t('importStaged', { count: stage.additions.length })}</div>
                      <div className="vh__stagelist">
                        {stage.additions.map(p => {
                          const meta = profileMeta(p);
                          return (
                            <div key={p.id} className="vh__stagerow is-ok">
                              <FileCheck2 size={14} />
                              <span className="vh__rm">
                                <b><span className="vh__cc">{meta.cc}</span>{p.name}</b>
                                <span>{p.kind === 'openvpn' ? t('importOpenVpn') : t('importWireGuard')} · {t('importValid')}</span>
                              </span>
                              <span className="vh__latency is-fast">✓</span>
                            </div>
                          );
                        })}
                      </div>
                    </>
                  )}
                  {stage.duplicates.length > 0 && (
                    <>
                      <div className="vh__sech" style={{ marginTop: 10 }}>{t('importDupes', { count: stage.duplicates.length })}</div>
                      <div className="vh__stagelist">
                        {stage.duplicates.map((name, i) => (
                          <div key={`d-${name}-${i}`} className="vh__stagerow is-dupe">
                            <Server size={14} />
                            <span className="vh__rm"><b>{name}</b><span>{t('importDuplicateLabel')}</span></span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                  {stage.rejected.length > 0 && (
                    <>
                      <div className="vh__sech" style={{ marginTop: 10 }}><FileX2 size={12} />{t('importRejected', { count: stage.rejected.length })}</div>
                      <div className="vh__stagelist">
                        {stage.rejected.map((r, i) => (
                          <div key={`r-${r.name}-${i}`} className="vh__stagerow is-bad">
                            <FileX2 size={14} />
                            <span className="vh__rm"><b>{r.name}</b><span>{t('importRejectedLabel')} · {r.reason}</span></span>
                            <span className="vh__latency is-slow">✕</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </section>
              ) : (
                !stageBusy && <div className="vh__note">{t('importEmptyStage')}</div>
              )}

              <div className="vh__host">
                <ShieldCheck size={15} />
                <span><b>{t('importEncrypted')}</b>{t('importDeviceKey')}</span>
              </div>

              {(error || statusError) && <div className="vh__error">{error || statusError}</div>}
            </div>
          </>
        ) : (
          <>
        <header className="vh__dh">
          <span className="vh__dhic" data-accent={accent}>
            {selectedProfile ? <Server size={20} /> : <Shield size={20} />}
          </span>
          <span className="vh__dhm">
            <h1>{selectedProfile?.name ?? activeProfileName ?? t('appTitle')}</h1>
            <span>
              {selectedProfile && (
                <>
                  <span className={`vh__chip ${activeProfileName === selectedProfile.name && connected ? 'ok' : 'mut'}`}>
                    {activeProfileName === selectedProfile.name && connected ? t('connectedUpper') : t('ready')}
                  </span>
                  <span className="vh__cc">{selectedMeta?.cc}</span>
                  <span className="vh__chip mut">{selectedProfile.kind === 'openvpn' ? t('openvpn') : t('wireguard')}</span>
                  {selectedMeta?.region} · {selectedMeta?.endpoint}
                </>
              )}
              {!selectedProfile && t('selectImport')}
            </span>
          </span>
          <span className="vh__dhacts">
            {tunnelActive
              ? (
                <>
                  {canConnect && (
                    <button className="vh__btn compact" onClick={() => setConfirm('reconnect')} disabled={busy}>
                      <RefreshCw size={11} />{t('reconnect')}
                    </button>
                  )}
                  <button className="vh__btn compact warn" onClick={() => setConfirm('disconnect-blocked')} disabled={busy}>
                    <Power size={11} />{t('disconnect')}
                  </button>
                </>
              )
              : <button className="vh__btn compact main" onClick={() => setConfirm('connect')} disabled={busy || !canConnect}><PlugZap size={11} />{t('connect')}</button>}
          </span>
        </header>

        <div className="vh__scrolld">
          {isEmpty ? (
            <section className="vh__first">
              <span className="vh__firstmk"><Shield size={26} /></span>
              <b>{t('emptyTitle')}</b>
              <span className="vh__firstsub">{t('emptyBody')}</span>
              <button
                type="button"
                className="vh__drop"
                disabled={!nativeControls}
                onClick={openImport}
                onDragOver={event => { event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; }}
                onDrop={event => {
                  event.preventDefault();
                  const files = Array.from(event.dataTransfer.files ?? []);
                  if (!files.length) return;
                  setScreen('import');
                  setSettingsOpen(true);
                  setError('');
                  setNotice('');
                  void stageFiles(files);
                }}
              >
                <FolderDown size={22} />
                <b>{t('emptyDropTitle')}</b>
                <span>{t('emptyDropBody')}</span>
              </button>
              <button className="vh__btn main" onClick={openImport} disabled={!nativeControls}>
                <FolderDown size={13} />{t('emptyImport')}
              </button>
              <span className="vh__firstfoot">{t('emptyFoot')}</span>
              {(statusError || error) && <div className="vh__error">{statusError || error}</div>}
              {notice && <div className="vh__note">{notice}</div>}
            </section>
          ) : (
            <>
          <section className={`vh__conn ${accent}`}>
            <span className="vh__shield"><HeroIcon size={26} /></span>
            <span className="vh__connm">
              <span className="vh__connst">{({ disconnected_open: t('phaseDisconnectedOpen'), disconnected_blocked: t('phaseDisconnectedBlocked'), connecting_blocked: t('phaseConnecting'), connected: t('phaseConnected'), degraded_blocked: t('phaseDegraded'), error_blocked: t('phaseError') } as Record<string, string>)[phase] ?? phase}</span>
              <span className="vh__connsub">
                {connected
                  ? [
                      activeProfileName,
                      status?.interface ? t('viaTunnel', { interface: String(status.interface) }) : t('tunnelUp'),
                    ].filter(Boolean).join(' · ')
                  : blocked ? t('tunnelDownBlocked') : t('noTunnelOpen')}
              </span>
            </span>
            <span className="vh__connwhen">
              <b>
                {tunnelLive
                  ? (liveUptime ?? '—')
                  : blocked
                    ? '0 B'
                    : (exitIpBusy ? '…' : (exitIp ?? '—'))}
              </b>
              <span className="vh__connlbl">
                {tunnelLive
                  ? t('uptime')
                  : blocked
                    ? t('leaked')
                    : t('exitIp')}
              </span>
              {/* Exit IP: refresh icon before the address (under uptime when tunnel is live). */}
              {tunnelLive && (!blocked || tunnelLive) && (
                <span className="vh__exitip-row" title={exitIpErr || t('exitIp')}>
                  <button
                    type="button"
                    className="vh__exitip"
                    onClick={() => void probeExitIp()}
                    disabled={exitIpBusy || !window.api.vpnProbeExitIp}
                    aria-label={t('exitIpRefresh')}
                    title={t('exitIpRefresh')}
                  >
                    <RefreshCw size={10} className={exitIpBusy ? 'vh__spin' : ''} />
                  </button>
                  <span className="vh__exitip-val">
                    {exitIpBusy && !exitIp ? '…' : (exitIp ?? '—')}
                  </span>
                </span>
              )}
              {/* Clearnet: big value already shows the IP — only a refresh control. */}
              {!tunnelLive && !blocked && (
                <button
                  type="button"
                  className="vh__exitip"
                  onClick={() => void probeExitIp()}
                  disabled={exitIpBusy || !window.api.vpnProbeExitIp}
                  aria-label={t('exitIpRefresh')}
                  title={t('exitIpRefresh')}
                >
                  <RefreshCw size={10} className={exitIpBusy ? 'vh__spin' : ''} />
                </button>
              )}
              {exitIpErr && <span className="vh__exitip-err" title={exitIpErr}>{exitIpErr}</span>}
            </span>
          </section>

          <div className="vh__gates">
            <div className={`vh__gate ${blocked ? (connected ? 'ok' : 'warn') : 'danger'}`}>
              <span className="vh__gic">{blocked ? <GlobeLock size={16} /> : <Globe size={16} />}</span>
              <span className="vh__gm"><span className="k">{t('clearnetEgress')}</span><span className="v">{blocked ? t('clearnetBlocked') : t('clearnetOpen')}</span></span>
            </div>
            <div className={`vh__gate ${killSwitch ? 'ok' : 'danger'}`}>
              <span className="vh__gic">{killSwitch ? <Lock size={16} /> : <LockOpen size={16} />}</span>
              <span className="vh__gm"><span className="k">{t('killSwitch')}</span><span className="v">{killSwitch ? t('activeStatus') : t('inactiveStatus')}</span></span>
            </div>
          </div>

          {connected && (
            <div className="vh__metrics">
              <div><b className="ok">{age(status?.handshake_age_secs).replace(' ago', '')}</b><span>{t('lastHandshake')}</span></div>
              <div><b>{bytes(status?.received_bytes)}</b><span>{t('received')}</span></div>
              <div><b>{bytes(status?.sent_bytes)}</b><span>{t('sent')}</span></div>
            </div>
          )}

          <div className="vh__host">
            <AlertTriangle size={15} />
            <span><b>{t('hostWideTitle')}</b>{t('hostWideBody')}</span>
          </div>

          <section className="vh__conf">
            <div className="vh__confh">
              <FileKey2 size={12} />
              {selectedProfile ? `${selectedProfile.name}.${selectedProfile.kind === 'openvpn' ? 'ovpn' : 'conf'}` : t('profilePreview')}
              {selectedProfile && (
                <button className="vh__ico" title={t('copyConfig')} onClick={() => void navigator.clipboard.writeText(redactVpnProfileSecrets(configText))}>
                  <Copy size={12} />
                </button>
              )}
            </div>
            {selectedProfile?.kind === 'openvpn' ? (
              <div className="vh__unsupported">
                <b>{t('openvpnLoaded')}</b>
                <p>{t('openvpnUnsupported')}</p>
              </div>
            ) : selectedProfile && isVirtualRandomProfile(selectedProfile) ? (
              <div className="vh__unsupported">
                <b>{selectedProfile.name}</b>
                <p>{t('virtualRandomHint')}</p>
              </div>
            ) : selectedProfile && confLines.length ? (
              <div className="vh__confbody">
                {confLines.map((line, i) => {
                  if (line.kind === 'section') return <div key={i} className="grp">{line.text}</div>;
                  if (line.kind === 'kv') {
                    return (
                      <div key={i} className="ln">
                        <span className="k">{line.key}</span>
                        {' = '}
                        <span className={line.secret ? 'v mask' : 'v hi'}>{line.value}</span>
                      </div>
                    );
                  }
                  return line.text ? <div key={i} className="ln muted">{line.text}</div> : <div key={i} className="ln pad" />;
                })}
              </div>
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
              <div className="r"><Waypoints size={13} /><span>{t('protocol')}</span><b>{selectedProfile.kind === 'openvpn' ? `${t('openvpn')} · ${t('preview')}` : t('wireguard')}</b></div>
              <div className="r"><Server size={13} /><span>{t('endpoint')}</span><b>{selectedMeta?.endpoint}</b></div>
              <div className="r"><GlobeLock size={13} /><span>{t('allowedIps')}</span><b>{configLine(configText, 'AllowedIPs')}</b></div>
              {selectedProfile.kind === 'wireguard' && !isRandomProfile(selectedProfile) && (
                <div className="r"><Gauge size={13} /><span>{t('handshakeLatency')}</span><b className={latencyTier(latencies[selectedProfile.id]) === 'fast' ? 'ok' : ''}>{latencies[selectedProfile.id] == null ? '—' : `${latencies[selectedProfile.id]}ms`}</b></div>
              )}
            </div>
          )}

          {tunnelActive ? (
            <section className="vh__card">
              <div className="vh__sech"><Power size={12} />{t('endSession')}</div>
              <div className="vh__btns">
                <button className="vh__btn session warn wide" onClick={() => setConfirm('disconnect-blocked')} disabled={busy}><Lock size={11} />{t('stayBlocked')}</button>
                <button className="vh__btn session danger wide" onClick={() => setConfirm('restore')} disabled={busy}><Globe size={11} />{t('restoreClearnet')}</button>
              </div>
              <p className="vh__p"><b>{t('stayBlockedHint')}</b> {t('stayBlockedBody')} <b>{t('restoreHint')}</b> {t('restoreClearnetBody')}</p>
            </section>
          ) : (
            <section className="vh__card">
              <div className="vh__sech"><Shield size={12} />{t('recover')}</div>
              <div className="vh__btns">
                <button className="vh__btn recovery main wide" onClick={() => setConfirm('connect')} disabled={busy || !canConnect}><PlugZap size={11} />{t('connect')} {selectedProfile?.name ?? t('selectImport')}</button>
                {killSwitch
                  ? <button className="vh__btn recovery danger wide" onClick={() => setConfirm('disable-killswitch')} disabled={busy || !nativeControls}><LockOpen size={11} />{t('disableKill')}</button>
                  : <button className="vh__btn recovery wide" onClick={() => setConfirm('recover')} disabled={busy || !nativeControls}><Lock size={11} />{t('rearm')}</button>}
              </div>
              <p className="vh__p">{blocked ? t('reconnectOrRestore') : t('clearnetConnecting')}</p>
            </section>
          )}

          {cleanupRequired && (
            <button className="vh__emergency" onClick={() => setConfirm('emergency-restore')} disabled={busy || !window.api.vpnEmergencyRestore}>
              {t('emergency')}
            </button>
          )}
          {!nativeControls && <div className="vh__note">{t('nativeRequired')}</div>}
          {notice && <div className="vh__note">{notice}</div>}
          {(statusError || error) && <div className="vh__error">{statusError || error}</div>}
            </>
          )}
        </div>
          </>
        )}
      </main>

      {confirm && <Confirm action={confirm} busy={busy} error={error} onCancel={() => !busy && setConfirm(null)} onConfirm={() => void run()} t={t} />}
    </div>
  );
}

function ProfileRow({ profile, latency, probed, probing, runActive, selected, active, onPick, onRemove, t }: {
  profile: VpnProfile;
  latency?: number | null;
  /** True only after this profile's probe finished (success or timeout). */
  probed: boolean;
  /** True while this profile is in the active probe batch. */
  probing: boolean;
  /** True while any speed-test batch is still running. */
  runActive: boolean;
  selected: boolean;
  active: boolean;
  onPick: () => void;
  onRemove: () => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}) {
  const meta = profileMeta(profile);
  const random = isRandomProfile(profile);
  const flag = random ? null : countryFlag(meta.cc);
  const tier = latencyTier(latency);
  const hasSample = typeof latency === 'number' && Number.isFinite(latency);
  // WireGuard peers participate in speed tests; OpenVPN / random are special-cased.
  const testable = profile.kind === 'wireguard' && !random;
  // Pending = queued or in-flight. Never paint "timeout" mid-run — only after the full pass ends.
  const pending = testable && (runActive || probing) && !hasSample;
  const showLatency = random || hasSample || pending || (probed && !runActive);
  let latencyText = '';
  if (random) latencyText = t('latencyAuto');
  else if (hasSample) latencyText = `${latency}ms`;
  else if (pending) latencyText = '…';
  else if (probed) latencyText = t('latencyTimeout');
  return (
    <button type="button" className={`vh__row${selected ? ' is-on' : ''}${random ? ' is-rand' : ''}`} onClick={onPick} title={profile.sourcePath}>
      <span className={`vh__ric${flag ? ' is-flag' : random ? ' is-random' : ''}`}>
        {random ? <Shuffle size={14} /> : flag ?? <Server size={14} />}
        {active && <span className="vh__st-dot" />}
      </span>
      <span className="vh__rm">
        <b><span className={`vh__cc${random ? ' rand' : ''}`}>{meta.cc}</span>{profile.name}</b>
        <span>{profile.kind === 'openvpn' ? `${t('openvpn')} · ${t('preview')}` : t('wireguard')} · {meta.region}{active ? ` · ${t('live')}` : ''}</span>
      </span>
      {showLatency && (
        <span className={`vh__latency${tier !== 'none' ? ` is-${tier}` : random || pending ? ' is-fast' : ''}`}>
          {latencyText}
        </span>
      )}
      {!isVirtualRandomProfile(profile) && (
        <span
          role="button"
          tabIndex={0}
          className="vh__del"
          title={t('removeProfile')}
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
      )}
    </button>
  );
}

function Confirm({ action, busy, error, onCancel, onConfirm, t }: {
  action: Exclude<ConfirmAction, null>;
  busy: boolean;
  error: string;
  onCancel: () => void;
  onConfirm: () => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}) {
  const copy: Record<Exclude<ConfirmAction, null>, [string, string]> = {
    connect: [t('connectQ'), t('connectBody')],
    reconnect: [t('reconnectQ'), t('reconnectBody')],
    'disconnect-blocked': [t('disconnectQ'), t('disconnectBody')],
    restore: [t('restoreQ'), t('restoreBody')],
    'disable-killswitch': [t('disableQ'), t('disableBody')],
    'enable-killswitch': [t('enableKsQ'), t('enableKsBody')],
    'disable-dns-filter': [t('dnsFilterOffQ'), t('dnsFilterOffBody')],
    'enable-dns-filter': [t('dnsFilterOnQ'), t('dnsFilterOnBody')],
    recover: [t('recoverQ'), t('recoverBody')],
    'emergency-restore': [t('emergencyQ'), t('emergencyBody')],
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
          <button className="vh__btn" onClick={onCancel} disabled={busy}>{t('cancel')}</button>
          <button className="vh__btn main" onClick={onConfirm} disabled={busy}>{busy ? t('authorizing') : t('confirm')}</button>
        </div>
      </div>
    </div>
  );
}

export default VpnView;
