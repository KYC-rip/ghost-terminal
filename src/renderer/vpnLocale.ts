export type VpnLocale = 'en' | 'es' | 'ru' | 'zh' | 'ja' | 'fa';

type VpnMessages = Record<string, string>;

const en: VpnMessages = {
  connected: 'Connected', blocked: 'Blocked', clearnet: 'Clearnet', refreshStatus: 'Refresh status',
  collapseSidebar: 'Collapse sidebar', expandSidebar: 'Expand sidebar', filterServers: 'filter servers',
  importProfiles: 'Import profiles (.zip, .conf, .ovpn)', encryptedMerge: 'Encrypted on this device · merge import',
  importBegin: 'Import a profile bundle to begin', testSpeeds: 'Test speeds', testing: 'Testing…', fastest: 'Fastest',
  probing: 'Probing {{count}} servers…', testedNow: 'Tested just now', notTested: 'Not tested yet', sortedFastest: ' · sorted fastest first',
  pinned: 'Pinned', profiles: 'Profiles', noMatches: 'No matching profiles.', importHint: 'Import a WireGuard .conf, OpenVPN .ovpn, or ZIP bundle.',
  removeProfile: 'Remove profile', tunnelUp: 'tunnel up', noTunnelNothing: 'no tunnel · nothing leaves', noTunnelDirect: 'no tunnel · direct egress',
  killActive: 'Kill-switch active', killOff: 'Kill-switch off', failClosedHost: 'egress fail-closed · host-wide', clearnetTraffic: 'traffic can use clearnet',
  ready: 'READY', connectedUpper: 'CONNECTED', wireguard: 'WIREGUARD', openvpn: 'OPENVPN', preview: 'preview', live: 'live',
  selectImport: 'Select or import a profile', protocol: 'Protocol', endpoint: 'Endpoint', allowedIps: 'Allowed IPs',
  hostTitle: 'HOST-WIDE NETWORK CONTROL', hostBody: 'WireGuard routes and the kill-switch apply to the whole computer, not just RipleyOS. Other apps and users are routed through the VPN, or blocked, until the tunnel is restored or clearnet is explicitly reopened.',
  disconnectSession: 'End this session', disconnect: 'Disconnect', stayBlocked: 'Disconnect · stay blocked', restoreClearnet: 'Disconnect · restore clearnet',
  recover: 'Recover', connect: 'Connect', disableKill: 'Disable kill-switch', rearm: 'Re-arm blocked state',
  failClosedHint: 'Fail-closed is holding egress shut. Reconnect or explicitly restore clearnet.', clearnetHint: 'You are on clearnet. Connecting installs the host-wide block before the tunnel comes up.',
  nativeRequired: 'VPN mutations require the trusted native Tauri host.', emergency: 'Emergency restore clearnet',
  cancel: 'Cancel', confirm: 'Confirm', authorizing: 'Authorizing…',
  connectQ: 'Connect VPN?', connectBody: 'This changes routing for the whole computer. The broker installs a host-wide fail-closed block before bringing up WireGuard.',
  disconnectQ: 'Disconnect and stay blocked?', disconnectBody: 'This tears down WireGuard but keeps the host-wide egress block. Other apps remain offline until you restore clearnet or reconnect.',
  restoreQ: 'Restore clearnet?', restoreBody: 'This re-opens non-VPN networking for the whole computer after disconnecting the tunnel.',
  disableQ: 'Disable kill-switch?', disableBody: 'This removes the host-wide block. Traffic from any app may leave over clearnet if the VPN is not connected.',
  recoverQ: 'Recover blocked state?', recoverBody: 'The broker will reconcile the whole computer toward an offline, blocked state.',
  emergencyQ: 'Emergency restore clearnet?', emergencyBody: 'BREAK GLASS: force teardown and remove the host-wide block despite dirty cleanup state. Other apps may immediately resume clearnet traffic.',
  vpnMutations: 'VPN mutations require the trusted native host window.', chooseConfig: 'Choose or paste a WireGuard configuration first.',
  disconnected: 'Disconnected', connecting: 'Connecting…', degraded: 'Degraded', error: 'Error',
  lastHandshake: 'Last handshake', received: 'Received', sent: 'Sent',
  noMatching: 'No matching profiles.', importProfilesHint: 'Import a WireGuard .conf, OpenVPN .ovpn, or ZIP bundle.',
  killSwitch: 'Kill-switch', active: 'Active', off: 'Off', egress: 'egress', clearnetEgress: 'Clearnet egress',
  open: 'Open', handshake: 'handshake', hostNote: 'Read-only status is shown here; VPN mutations require the trusted native host window.',
  copyConfig: 'Copy redacted config', profilePreview: 'profile preview', openvpnLoaded: 'OpenVPN profile loaded',
  openvpnUnsupported: 'It is encrypted and inspectable, but the current broker only connects WireGuard. OpenVPN requires its own fail-closed broker state machine.',
  disconnectBeforeRemove: 'Disconnect the active profile before removing it.', storedProfilesError: 'Stored profiles could not be unlocked: {{error}}',
  speedHostError: 'Speed testing requires the current native host build.', speedError: 'Could not test server speeds: {{error}}',
  noProfilesAdded: 'No profiles added — every imported name already exists.', imported: 'Imported {{count}} profile{{plural}} · existing names were left unchanged.',
  removed: 'Removed {{name}}.', removeError: 'Could not remove {{name}}: {{error}}', selectConfig: 'Choose or paste a WireGuard configuration first.',
  mutationsRequired: 'VPN mutations require the trusted native host window.', emergencyUnavailable: 'Emergency recovery is unavailable in this native build.',
  phaseDisconnectedOpen: 'Disconnected · clearnet', phaseDisconnectedBlocked: 'Disconnected · blocked', phaseConnecting: 'Connecting…',
  phaseConnected: 'Connected', phaseDegraded: 'Degraded · blocked', phaseError: 'Error · blocked',
  tunnelDownBlocked: 'tunnel down · the kill-switch is holding egress', noTunnelOpen: 'no tunnel · direct network access is open',
  clearnetBlocked: 'Blocked', clearnetOpen: 'Open', activeStatus: 'Active', inactiveStatus: 'Off',
  hostWideTitle: 'HOST-WIDE NETWORK CONTROL', hostWideBody: 'WireGuard routes and the kill-switch apply to the whole computer, not just RipleyOS. Other apps and users are routed through the VPN, or blocked, until the tunnel is restored or clearnet is explicitly reopened.',
  endSession: 'End this session', stayBlockedHint: 'Stay blocked', stayBlockedBody: 'drops the tunnel but keeps egress fail-closed.', restoreHint: 'Restore clearnet', restoreClearnetBody: 'reopens direct traffic and exposes this machine’s real IP.',
  reconnectOrRestore: 'Fail-closed is holding egress shut. Reconnect or explicitly restore clearnet.', clearnetConnecting: 'You are on clearnet. Connecting installs the host-wide block before the tunnel comes up.',
  appTitle: 'Ripley VPN',
};

const translations: Record<VpnLocale, VpnMessages> = { en, es: {
  connected: 'Conectado', blocked: 'Bloqueado', clearnet: 'Internet abierto', refreshStatus: 'Actualizar estado', collapseSidebar: 'Contraer barra lateral', expandSidebar: 'Expandir barra lateral', filterServers: 'filtrar servidores', importProfiles: 'Importar perfiles (.zip, .conf, .ovpn)', testSpeeds: 'Probar velocidades', testing: 'Probando…', fastest: 'Más rápido', recover: 'Recuperar', connect: 'Conectar', disconnect: 'Desconectar', cancel: 'Cancelar', confirm: 'Confirmar', authorizing: 'Autorizando…', lastHandshake: 'Último handshake', received: 'Recibido', sent: 'Enviado', hostTitle: 'CONTROL DE RED DE TODO EL HOST', stayBlocked: 'Desconectar · mantener bloqueo', restoreClearnet: 'Desconectar · restaurar internet', disableKill: 'Desactivar kill-switch', rearm: 'Reactivar estado bloqueado',
}, ru: { connected: 'Подключено', blocked: 'Заблокировано', clearnet: 'Открытая сеть', refreshStatus: 'Обновить состояние', collapseSidebar: 'Свернуть боковую панель', expandSidebar: 'Развернуть боковую панель', filterServers: 'фильтр серверов', importProfiles: 'Импорт профилей (.zip, .conf, .ovpn)', testSpeeds: 'Проверить скорость', testing: 'Проверка…', fastest: 'Быстрый', recover: 'Восстановить', connect: 'Подключить', disconnect: 'Отключить', cancel: 'Отмена', confirm: 'Подтвердить', authorizing: 'Авторизация…', lastHandshake: 'Последнее рукопожатие', received: 'Получено', sent: 'Отправлено', hostTitle: 'СЕТЕВОЕ УПРАВЛЕНИЕ ВСЕГО ХОСТА', stayBlocked: 'Отключить · оставить блокировку', restoreClearnet: 'Отключить · восстановить сеть', disableKill: 'Отключить kill-switch', rearm: 'Восстановить блокировку' }, zh: { connected: '已連線', blocked: '已封鎖', clearnet: '明網', refreshStatus: '重新整理狀態', collapseSidebar: '收合側欄', expandSidebar: '展開側欄', filterServers: '篩選伺服器', importProfiles: '匯入設定檔 (.zip、.conf、.ovpn)', testSpeeds: '測試速度', testing: '測試中…', fastest: '最快', recover: '復原', connect: '連線', disconnect: '斷線', cancel: '取消', confirm: '確認', authorizing: '授權中…', lastHandshake: '上次握手', received: '已接收', sent: '已傳送', hostTitle: '整台主機的網路控制', stayBlocked: '斷線 · 保持封鎖', restoreClearnet: '斷線 · 恢復明網', disableKill: '停用 kill-switch', rearm: '重新啟用封鎖' }, ja: { connected: '接続済み', blocked: 'ブロック中', clearnet: 'クリアネット', refreshStatus: '状態を更新', collapseSidebar: 'サイドバーを折りたたむ', expandSidebar: 'サイドバーを展開', filterServers: 'サーバーを絞り込む', importProfiles: 'プロファイルを読み込む (.zip、.conf、.ovpn)', testSpeeds: '速度を測定', testing: '測定中…', fastest: '最速', recover: '復元', connect: '接続', disconnect: '切断', cancel: 'キャンセル', confirm: '確認', authorizing: '承認中…', lastHandshake: '最終ハンドシェイク', received: '受信', sent: '送信', hostTitle: 'ホスト全体のネットワーク制御', stayBlocked: '切断 · ブロックを維持', restoreClearnet: '切断 · クリアネットを復元', disableKill: 'kill-switchを無効化', rearm: 'ブロック状態を再設定' }, fa: { connected: 'متصل', blocked: 'مسدود', clearnet: 'اینترنت آزاد', refreshStatus: 'تازه‌سازی وضعیت', collapseSidebar: 'جمع کردن نوار کناری', expandSidebar: 'باز کردن نوار کناری', filterServers: 'فیلتر سرورها', importProfiles: 'وارد کردن پروفایل (.zip، .conf، .ovpn)', testSpeeds: 'آزمون سرعت', testing: 'در حال آزمون…', fastest: 'سریع‌ترین', recover: 'بازیابی', connect: 'اتصال', disconnect: 'قطع اتصال', cancel: 'لغو', confirm: 'تأیید', authorizing: 'در حال مجوزدهی…', lastHandshake: 'آخرین handshake', received: 'دریافت‌شده', sent: 'ارسال‌شده', hostTitle: 'کنترل شبکه در سراسر میزبان', stayBlocked: 'قطع · حفظ مسدودی', restoreClearnet: 'قطع · بازگردانی اینترنت آزاد', disableKill: 'غیرفعال کردن kill-switch', rearm: 'فعال‌سازی دوباره مسدودی' } };

Object.assign(translations.zh, {
  appTitle: 'Ripley VPN', tunnelUp: '通道已啟用', noTunnelNothing: '無通道 · 沒有流量離開', noTunnelDirect: '無通道 · 直接連線',
  pinned: '已釘選', profiles: '設定檔', noMatching: '沒有符合的設定檔。', importProfilesHint: '匯入 WireGuard、OpenVPN 設定檔或 ZIP 套件。',
  killActive: '終止開關已啟用', killOff: '終止開關已關閉', failClosedHost: '出口封鎖 · 整台主機', clearnetTraffic: '流量可使用明網',
  ready: '就緒', connectedUpper: '已連線', wireguard: 'WIREGUARD', openvpn: 'OPENVPN', preview: '預覽', live: '使用中', selectImport: '選取或匯入設定檔',
  protocol: '通訊協定', endpoint: '端點', allowedIps: '允許的 IP', lastHandshake: '上次握手', received: '已接收', sent: '已傳送',
  clearnetEgress: '明網出口', clearnetBlocked: '已封鎖', clearnetOpen: '開啟', killSwitch: '終止開關', activeStatus: '啟用', inactiveStatus: '關閉',
  handshake: '握手', egress: '出口', hostWideTitle: '整台主機的網路控制', endSession: '結束此工作階段', profilePreview: '設定檔預覽', copyConfig: '複製已遮蔽的設定',
  openvpnLoaded: '已載入 OpenVPN 設定檔', removeProfile: '移除設定檔', cancel: '取消', confirm: '確認',
});

export function createVpnTranslator(locale: string | null | undefined): (key: string, vars?: Record<string, string | number>) => string {
  const candidate = typeof locale === 'string' ? locale : '';
  const selected = (Object.prototype.hasOwnProperty.call(translations, candidate) ? candidate : 'en') as VpnLocale;
  return (key, vars) => {
    let value = translations[selected][key] ?? en[key] ?? key;
    for (const [name, replacement] of Object.entries(vars ?? {})) value = value.replace(`{{${name}}}`, String(replacement));
    return value;
  };
}
