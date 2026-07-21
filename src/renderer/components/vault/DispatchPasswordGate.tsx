import { Lock, Loader2 } from 'lucide-react';

interface DispatchPasswordGateProps {
  password: string;
  passwordError: string;
  isVerifying: boolean;
  onPasswordChange: (val: string) => void;
  onVerify: () => void;
  onCancel: () => void;
}

export function DispatchPasswordGate({
  password,
  passwordError,
  isVerifying,
  onPasswordChange,
  onVerify,
  onCancel
}: DispatchPasswordGateProps) {
  return (
    <div className="absolute inset-0 z-10 bg-xmr-surface/95 backdrop-blur-sm flex flex-col items-center justify-center p-8 animate-in fade-in duration-200">
      <Lock size={36} className="text-xmr-accent mb-4" />
      <h4 className="text-sm font-black uppercase text-xmr-accent tracking-widest mb-1">Authorization Required</h4>
      <p className="text-[11px] text-xmr-dim uppercase tracking-wider mb-6">Enter vault password to authorize transaction</p>
      <input
        autoFocus
        type="password"
        value={password}
        onChange={(e) => onPasswordChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') onVerify();
          if (e.key === 'Escape') onCancel();
        }}
        placeholder="••••••••••••"
        className={`w-full max-w-xs bg-xmr-base border p-3 text-xl font-black text-xmr-green text-center focus:border-xmr-accent outline-none transition-all ${
          passwordError ? 'border-xmr-error' : 'border-xmr-border'
        }`}
      />
      {passwordError && <div className="text-[11px] text-xmr-error uppercase mt-2 animate-pulse">{passwordError}</div>}
      <div className="flex gap-3 mt-6 w-full max-w-xs">
        <button
          onClick={onCancel}
          className="flex-1 py-2.5 border border-xmr-border text-xmr-dim font-black uppercase tracking-widest text-[11px] cursor-pointer hover:border-xmr-accent transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={onVerify}
          disabled={!password || isVerifying}
          className="flex-1 py-2.5 bg-xmr-accent text-xmr-base font-black uppercase tracking-widest text-[11px] cursor-pointer hover:bg-xmr-green transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {isVerifying ? <Loader2 size={12} className="animate-spin" /> : <Lock size={12} />}
          {isVerifying ? 'Verifying...' : 'Authorize'}
        </button>
      </div>
    </div>
  );
}
