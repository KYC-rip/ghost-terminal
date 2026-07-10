import { useState, useRef } from 'react';
import { X, Send, Ghost } from 'lucide-react';
import { useVault } from '../../contexts/VaultContext';
import { DispatchPasswordGate } from './DispatchPasswordGate';
import { DirectSendTab } from './DirectSendTab';
import { GhostSendTab } from './GhostSendTab';
import { isStressnet } from '../../utils/networkMode';

interface DispatchModalProps {
  onClose: () => void;
  initialAddress?: string;
  sourceSubaddressIndex?: number;
  inline?: boolean;
}

type Tab = 'direct' | 'ghost';

export function DispatchModal({ onClose, initialAddress = '', sourceSubaddressIndex, inline }: DispatchModalProps) {
  const { activeId, outputs } = useVault();
  const [tab, setTab] = useState<Tab>('direct');

  // --- Password Confirmation ---
  const [showPasswordGate, setShowPasswordGate] = useState(false);
  const [password, setPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const pendingActionRef = useRef<(() => Promise<void>) | null>(null);

  const requirePassword = (action: () => Promise<void>) => {
    pendingActionRef.current = action;
    setPassword('');
    setPasswordError('');
    setShowPasswordGate(true);
  };

  const verifyAndExecute = async () => {
    if (!password) return;
    setIsVerifying(true);
    setPasswordError('');
    try {
      const res = await window.api.walletAction('open', { name: activeId, pwd: password });
      if (!res.success) throw new Error(res.error || 'Invalid password');
      setShowPasswordGate(false);
      if (pendingActionRef.current) await pendingActionRef.current();
    } catch (e: any) {
      setPasswordError(e.message?.includes('invalid password') ? 'WRONG_PASSWORD' : e.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const content = (
      <div className={`w-full ${inline ? '' : 'max-w-xl bg-xmr-surface border border-xmr-border rounded-sm'} relative flex flex-col ${inline ? 'h-full' : 'max-h-[85vh]'} overflow-hidden`}>
        {/* ══ PASSWORD GATE ══ */}
        {showPasswordGate && (
          <DispatchPasswordGate
            password={password}
            passwordError={passwordError}
            isVerifying={isVerifying}
            onPasswordChange={(val) => {
              setPassword(val);
              setPasswordError('');
            }}
            onVerify={verifyAndExecute}
            onCancel={() => setShowPasswordGate(false)}
          />
        )}

        {/* Header — matches tab bar style when inline */}
        <div className={`flex items-center justify-between ${inline ? 'px-3 py-2 bg-xmr-surface/50' : 'px-6 py-4'} border-b border-xmr-border/${inline ? '15' : '40'}`}>
          <div className="flex gap-1 items-center">
            {/* Sub-tabs: Direct / Ghost */}
            {[
              { id: 'direct' as const, label: 'Direct XMR', icon: <Send size={12} /> },
              // Ghost Send needs the swap API, which has no stressnet support
              ...(isStressnet() ? [] : [{ id: 'ghost' as const, label: 'Ghost Send', icon: <Ghost size={12} /> }]),
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`px-4 py-2 text-[11px] font-black uppercase tracking-widest transition-all rounded-sm flex items-center gap-1.5 cursor-pointer ${
                  tab === t.id
                    ? 'text-xmr-accent border border-xmr-accent/30 bg-xmr-accent/5'
                    : 'text-xmr-dim hover:text-xmr-accent border border-transparent'
                }`}
              >
                {t.icon} {t.label}
              </button>
            ))}
          </div>
          <button onClick={onClose} className="text-xmr-dim hover:text-xmr-accent transition-colors cursor-pointer p-1">
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-5">
          {tab === 'direct' && (
            <DirectSendTab
              initialAddress={initialAddress}
              sourceSubaddressIndex={sourceSubaddressIndex}
              outputs={outputs}
              onRequirePassword={requirePassword}
              onClose={onClose}
            />
          )}

          {tab === 'ghost' && <GhostSendTab onRequirePassword={requirePassword} onClose={onClose} />}
        </div>
      </div>
  );

  if (inline) return content;

  return (
    <div className="fixed top-0 bottom-0 right-0 left-[14rem] z-[100] flex items-center justify-center p-4 bg-xmr-base/90 backdrop-blur-md animate-in zoom-in-95 duration-300 font-black">
      {content}
    </div>
  );
}
