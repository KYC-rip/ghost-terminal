import React, { useState, useEffect } from 'react';
import { Shield, ShieldCheck, Users, Globe, ShieldAlert } from 'lucide-react';
import { Card } from './Card';
import { AuthForm } from './auth/AuthForm';
import { IdentitySwitcher } from './auth/IdentitySwitcher';
import { LogEntry } from '../contexts/VaultContext';

interface Identity { id: string; name: string; created: number; }

interface AuthViewProps {
  onUnlock: (password: string, newIdentityName?: string, restoreSeed?: string, restoreHeight?: number, seedLanguage?: string) => Promise<void>;
  isInitialSetup: boolean;
  identities: Identity[];
  activeId: string;
  onSwitchIdentity: (id: string) => void;
  onCreateIdentity: (name: string) => void;
  onPurgeIdentity: (id: string) => void;
  logs?: LogEntry[];
}

type SetupStep = 'AUTH' | 'LABEL' | 'MODE' | 'RESTORE' | 'NEW_PASSWORD';

export function AuthView({ onUnlock, isInitialSetup, identities, activeId, onSwitchIdentity, onCreateIdentity, onPurgeIdentity, logs = [] }: AuthViewProps) {
  const [routingMode, setRoutingMode] = useState<'tor' | 'clearnet'>('tor');
  const [step, setStep] = useState<SetupStep>('AUTH');
  const [hasInitialized, setHasInitialized] = useState(false);

  useEffect(() => {
    // Load initial network mode
    window.api.getConfig().then((config: any) => {
      setRoutingMode(config.routingMode || 'tor');
    });

  // Handle step transition after identity load
    if (!hasInitialized && identities.length > 0) {
      setStep('AUTH');
      setHasInitialized(true);
    } else if (!hasInitialized && identities.length === 0) {
      // First launch: skip to password creation directly (Exodus-style)
      setNewName('My_Wallet');
      setStep('NEW_PASSWORD');
    }
  }, [identities.length, hasInitialized]);

  // 🟢 2. Handle network toggle (persist directly to main process)
  const toggleNetwork = async () => {
    const newMode = routingMode === 'tor' ? 'clearnet' : 'tor';
    setRoutingMode(newMode);

    const config = await window.api.getConfig();
    await window.api.saveConfigAndReload({
      ...config,
      routingMode: newMode
    });
  };

  // Form States
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [restoreSeed, setRestoreSeed] = useState('');
  const [restoreHeight, setRestoreHeight] = useState('');
  const [newName, setNewName] = useState('');
  const [seedLanguage, setSeedLanguage] = useState('English');
  const [error, setError] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [appVersion, setAppVersion] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  // Clear any stale error when navigating between auth steps — a failed unlock's
  // "INVALID PASSWORD" must not linger on the create/restore screens.
  useEffect(() => { setError(''); }, [step]);

  useEffect(() => {
    window.api.getAppInfo().then(info => setAppVersion(info.version));
  }, []);

  const activeIdentity = identities.find(i => i.id === activeId) || identities[0];

  const handleClearCache = async () => {
    setIsProcessing(true);
    try {
      await window.api.clearCache();
      window.location.reload();
    } catch (err: any) {
      setError(`CACHE_PURGE_FAILED: ${err.message.toUpperCase()}`);
      setIsProcessing(false);
      setShowClearConfirm(false);
    }
  };

  const handleIdentityChange = (id: string) => {
    if (isProcessing) return;
    setError('');
    setPassword('');
    setConfirmPassword('');
    onSwitchIdentity(id);
  };

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isProcessing) return;

    // Validation logic
    if (step === 'RESTORE' || step === 'NEW_PASSWORD' || (step === 'LABEL' && isInitialSetup)) {
      if (password.length < 8) { setError('SECRET_TOO_SHORT: MIN 8 CHARS'); return; }
      if (password !== confirmPassword) { setError('PASSWORDS_DO_NOT_MATCH'); return; }
    }

    setIsProcessing(true);
    setError('');

    try {
      const height = restoreHeight ? parseInt(restoreHeight) : undefined;
      // 🚀 Call the new unlock in VaultContext
      await onUnlock(
        password,
        newName || undefined,
        step === 'RESTORE' ? restoreSeed : undefined,
        height,
        step === 'RESTORE' ? seedLanguage : undefined
      );
    } catch (err: any) {
      const msg = err.message || '';
      const lower = msg.toLowerCase();
      // A decrypt failure is almost always a wrong password (the AEAD check can't
      // tell a wrong key from a corrupt file). Show a clean, non-alarming message
      // and clear the field so the user retypes fresh.
      const badPassword =
        lower.includes('invalid_secret') ||
        lower.includes('invalid password') ||
        lower.includes('corrupted wallet');
      if (badPassword) {
        setError('ACCESS_DENIED: WRONG PASSWORD');
        setPassword('');
      } else if (msg.includes('UPLINK_TIMEOUT')) {
        // Transient — keep the (likely-correct) password so retry needs no retype.
        setError('UPLINK_TIMEOUT: TOR CIRCUIT FAILED');
      } else {
        setError(`ENGINE_ERROR: ${msg.toUpperCase()}`);
      }
      setIsProcessing(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-xmr-base text-xmr-green font-mono p-6 relative overflow-y-auto custom-scrollbar">
      <div className="fixed inset-0 scanline-overlay pointer-events-none z-50 opacity-[0.05]"></div>

      <div className="w-full max-w-md space-y-6 relative z-10 animate-in fade-in zoom-in-95 duration-500 py-10">
        {/* HEADER */}
        <div className="text-center space-y-3">
          <div className="inline-block p-3 rounded-full bg-xmr-green/10 border border-xmr-green/20 mb-1">
            {step === 'AUTH' ? <Shield size={40} className={isProcessing ? 'animate-pulse' : ''} /> : <ShieldCheck size={40} />}
          </div>
          <h1 className="text-2xl font-black uppercase text-xmr-green tracking-tight" style={{ fontFamily: 'var(--font-display)' }}>
            {step === 'RESTORE' ? 'Restore Wallet' : step === 'NEW_PASSWORD' ? (identities.length === 0 ? 'Create Your Wallet' : 'Set Password') : step === 'LABEL' ? 'Name Your Wallet' : 'Unlock Vault'}
          </h1>
          <div className="flex flex-col items-center gap-1">
            <div className="flex items-center justify-center gap-2 text-[11px] text-xmr-dim uppercase tracking-widest">
              <Users size={10} />
              <span>Active_ID: <span className="text-xmr-green font-black">{newName || activeIdentity?.name || 'INITIALIZING'}</span></span>
            </div>
            {appVersion && (
              <span className="text-[9px] font-black text-xmr-dim/50 tracking-widest uppercase">Ripley_Terminal_v{appVersion}</span>
            )}
          </div>
        </div>

        <Card topGradientAccentColor={step === 'AUTH' ? 'xmr-accent' : 'xmr-green'} className="p-8 shadow-2xl relative">
          <AuthForm
            step={step} setStep={setStep} isInitialSetup={isInitialSetup}
            password={password} setPassword={setPassword}
            confirmPassword={confirmPassword} setConfirmPassword={setConfirmPassword}
            restoreSeed={restoreSeed} setRestoreSeed={setRestoreSeed}
            restoreHeight={restoreHeight} setRestoreHeight={setRestoreHeight}
            newName={newName} setNewName={setNewName}
            seedLanguage={seedLanguage} setSeedLanguage={setSeedLanguage}
            error={error} isProcessing={isProcessing} logs={logs}
            handleUnlockSubmit={handleUnlockSubmit}
            handleCreateFinalize={() => { }}
          />

          {!isProcessing && step === 'AUTH' && (
            <IdentitySwitcher
              identities={identities}
              activeId={activeId}
              onSwitchIdentity={handleIdentityChange}
              onStartNew={() => {
                setNewName('');  // Clear input
                setStep('LABEL'); // Jump to new label setup step
              }}
              onPurge={onPurgeIdentity}
            />
          )}

          {/* 🛡️ TACTICAL NETWORK TOGGLE: Direct control of main process RoutingMode */}
          {!isProcessing && (
            <div className="mt-6 pt-4 border-t border-xmr-border/10 flex flex-col gap-3">
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  {routingMode === 'tor' ? <ShieldCheck size={12} className="text-xmr-green" /> : <Globe size={12} className="text-xmr-accent" />}
                  <span className="text-xs font-black uppercase tracking-widest text-xmr-dim">Uplink_Strategy</span>
                </div>
                <button
                  type="button"
                  onClick={toggleNetwork}
                  className={`px-2 py-0.5 rounded border text-xs font-black transition-all cursor-pointer ${routingMode === 'tor'
                    ? 'border-xmr-green/50 text-xmr-green hover:bg-xmr-green/10'
                    : 'border-xmr-accent/50 text-xmr-accent hover:bg-xmr-accent/10'
                    }`}
                >
                  {routingMode === 'tor' ? 'TOR_ONLY' : 'CLEARNET_ACTIVE'}
                </button>
              </div>

              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={12} className="text-xmr-accent/60" />
                  <span className="text-xs font-black uppercase tracking-widest text-xmr-dim">Tactical_Purge</span>
                </div>
                {!showClearConfirm ? (
                  <button
                    type="button"
                    onClick={() => setShowClearConfirm(true)}
                    className="text-[10px] font-black text-xmr-dim hover:text-xmr-accent uppercase tracking-widest transition-colors cursor-pointer border-b border-dashed border-xmr-dim/30"
                  >
                    Clear_Cache
                  </button>
                ) : (
                  <div className="flex items-center gap-3">
                    <span className="text-[9px] font-black text-xmr-accent uppercase animate-pulse">Confirm?</span>
                    <button
                      type="button"
                      onClick={handleClearCache}
                      className="text-[10px] font-black text-xmr-accent hover:bg-xmr-accent/10 px-2 py-0.5 border border-xmr-accent/30 uppercase tracking-widest transition-all cursor-pointer"
                    >
                      YES
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowClearConfirm(false)}
                      className="text-[10px] font-black text-xmr-dim hover:text-xmr-green uppercase tracking-widest transition-colors cursor-pointer"
                    >
                      NO
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </Card>

        {/* FOOTER */}
        <div className="text-center space-y-4 pt-4">
          <p className="text-xs text-xmr-dim uppercase leading-relaxed max-w-md mx-auto opacity-60 italic">
            IMPORTANT: Local password is the only key to decrypt your vault file. <br />
            Zero-knowledge isolation active.
          </p>
        </div>
      </div>
    </div>
  );
}