import React from 'react';
import { Lock, Skull, RefreshCw, Key, Download, Sparkles, ArrowLeft, Calendar, ChevronDown } from 'lucide-react';

interface LogEntry {
  msg: string;
  timestamp: number;
}

interface AuthFormProps {
  step: 'AUTH' | 'LABEL' | 'MODE' | 'RESTORE' | 'NEW_PASSWORD';
  setStep: (s: any) => void;
  isInitialSetup: boolean;
  
  // Form Values & Setters
  password: string; setPassword: (v: string) => void;
  confirmPassword: string; setConfirmPassword: (v: string) => void;
  restoreSeed: string; setRestoreSeed: (v: string) => void;
  restoreHeight: string; setRestoreHeight: (v: string) => void;
  newName: string; setNewName: (v: string) => void;
  seedLanguage: string; setSeedLanguage: (v: string) => void;
  
  // State
  error: string;
  isProcessing: boolean;
  logs: LogEntry[];
  
  // Actions
  handleUnlockSubmit: (e: React.FormEvent) => void;
  handleCreateFinalize: () => void; 
}

export function AuthForm({ 
  step, setStep, isInitialSetup,
  password, setPassword, confirmPassword, setConfirmPassword,
  restoreSeed, setRestoreSeed, restoreHeight, setRestoreHeight,
  newName, setNewName, seedLanguage, setSeedLanguage,
  error, isProcessing, logs,
  handleUnlockSubmit
}: AuthFormProps) {

  if (step === 'LABEL') {
    return (
      <form onSubmit={(e) => { e.preventDefault(); if(newName) setStep('MODE'); }} className="space-y-4 animate-in fade-in duration-300">
         <div className="space-y-1">
            <label className="text-[11px] font-black text-xmr-dim uppercase ml-1">Identity_Label</label>
            <input autoFocus type="text" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g. PRIMARY_VAULT" className="w-full bg-xmr-base border border-xmr-border p-3 text-lg font-black text-xmr-green outline-none focus:border-xmr-green transition-all" />
         </div>
         <button type="button" onClick={() => { if(newName) setStep('MODE'); }} disabled={!newName} className="w-full py-4 bg-xmr-green text-xmr-base font-black uppercase tracking-[0.2em] hover:bg-white hover:text-black transition-all disabled:opacity-50 cursor-pointer">Next_Step</button>
      </form>
    );
  }

  if (step === 'MODE') {
    return (
      <div className="grid grid-cols-1 gap-3 animate-in fade-in duration-300">
         <button type="button" onClick={() => setStep('NEW_PASSWORD')} className="p-5 border border-xmr-border bg-xmr-green/5 hover:border-xmr-green hover:bg-xmr-green/10 transition-all text-left group">
            <div className="flex items-center gap-3 mb-1"><Sparkles className="text-xmr-green" size={18} /><span className="text-sm font-black uppercase text-xmr-green">Generate_New</span></div>
            <p className="text-xs text-xmr-dim uppercase">Derive fresh 25-word mnemonic phrase.</p>
         </button>
         <button type="button" onClick={() => setStep('RESTORE')} className="p-5 border border-xmr-border bg-xmr-accent/5 hover:border-xmr-accent hover:bg-xmr-accent/10 transition-all text-left group">
            <div className="flex items-center gap-3 mb-1"><Download className="text-xmr-accent" size={18} /><span className="text-sm font-black uppercase text-xmr-accent">Restore_Existing</span></div>
            <p className="text-xs text-xmr-dim uppercase">Import identity from private backup seed.</p>
         </button>
         <button type="button" onClick={() => { if(isInitialSetup) setStep('LABEL'); else setStep('AUTH'); }} className="mt-2 text-[11px] text-xmr-dim hover:text-xmr-green uppercase flex items-center justify-center gap-2 transition-colors cursor-pointer"><ArrowLeft size={12}/> Back</button>
      </div>
    );
  }

  return (
    <form onSubmit={handleUnlockSubmit} className="space-y-5 animate-in slide-in-from-bottom-2 duration-300">
      {step === 'RESTORE' && (
        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-[11px] font-black text-xmr-dim uppercase ml-1 flex justify-between"><span>Mnemonic_Seed (25 words)</span><span className="text-xmr-accent font-black">STANDARD_ONLY</span></label>
            <textarea rows={2} value={restoreSeed} onChange={(e) => setRestoreSeed(e.target.value)} placeholder="word1 word2 ..." className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-[11px] font-black text-xmr-dim uppercase ml-1 flex items-center gap-2"><Calendar size={10} /> Restore_Height (Optional)</label>
              <input type="number" value={restoreHeight} onChange={(e) => setRestoreHeight(e.target.value)} placeholder="e.g. 3000000" className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none" />
            </div>
            <div className="space-y-1">
              <label className="text-[11px] font-black text-xmr-dim uppercase ml-1">Seed_Language</label>
              <div className="relative">
                <select
                  value={seedLanguage}
                  onChange={(e) => setSeedLanguage(e.target.value)}
                  className="w-full appearance-none bg-xmr-base border border-xmr-border p-3 pr-9 text-xs text-xmr-green focus:border-xmr-green outline-none cursor-pointer"
                >
                  {['English','Chinese (Simplified)','Japanese','Spanish','Portuguese','German','French','Italian','Dutch','Russian','Esperanto','Lojban'].map(lang => (
                    <option key={lang} value={lang} className="bg-xmr-base text-xmr-green">{lang}</option>
                  ))}
                </select>
                <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-xmr-dim pointer-events-none" />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-1">
        <label className="text-[11px] font-black text-xmr-dim uppercase ml-1">{step === 'AUTH' ? 'Vault_Secret' : 'Set_Master_Password'}</label>
        <div className="relative">
          <input autoFocus type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••••" className="w-full bg-xmr-base border border-xmr-border p-2 text-xl font-black text-xmr-green focus:border-xmr-green outline-none transition-all placeholder:opacity-20" />
          <Lock className="absolute right-4 top-1/2 -translate-y-1/2 text-xmr-dim opacity-30" size={20} />
        </div>
      </div>

      {step !== 'AUTH' && (
        <div className="space-y-1">
          <label className="text-[11px] font-black text-xmr-dim uppercase ml-1">Confirm_Password</label>
          <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="••••••••••••" className="w-full bg-xmr-base border border-xmr-border p-2 text-xl font-black text-xmr-green focus:border-xmr-green outline-none transition-all placeholder:opacity-20" />
        </div>
      )}

      {error && <div className="p-3 bg-red-900/20 border border-red-600/50 text-red-500 text-xs font-black uppercase flex items-center gap-2 animate-shake"><Skull size={14} /> {error}</div>}

      {isProcessing && logs.length > 0 && (
        <div className="p-3 bg-xmr-green/5 border border-xmr-green/10 rounded-sm space-y-1 overflow-hidden">
           {logs.slice(0, 3).map((log, i) => (
             <p key={i} className={`text-xs uppercase truncate font-black ${i === 0 ? 'text-xmr-green' : 'text-xmr-dim opacity-60'}`}>
               {'>'} {log.msg}
             </p>
           ))}
        </div>
      )}

      <div className="flex flex-col gap-3">
        <button disabled={isProcessing || !password || (step !== 'AUTH' && !confirmPassword)} className="w-full py-4 bg-xmr-green text-xmr-base font-black uppercase tracking-[0.3em] hover:bg-white hover:text-black transition-all flex items-center justify-center gap-3 group disabled:opacity-50 cursor-pointer">
          {isProcessing ? <><RefreshCw size={18} className="animate-spin" /> Authorizing...</> : <><Key size={18} className="group-hover:scale-110 transition-transform" /> {step === 'RESTORE' ? 'Restore Wallet' : step === 'NEW_PASSWORD' ? 'Create Wallet' : 'Unlock'}</>}
        </button>

        {!isProcessing && step === 'NEW_PASSWORD' && isInitialSetup && (
           <button type="button" onClick={() => setStep('RESTORE')} className="w-full text-[11px] text-xmr-dim hover:text-xmr-green uppercase flex items-center justify-center gap-2 transition-colors cursor-pointer"><Download size={12}/> Restore from Seed</button>
        )}
        {/* When existing wallets are present, EVERY setup step must offer an escape
            back to Unlock — otherwise a user who enters create/restore is stranded
            (and could accidentally CREATE a new empty wallet). */}
        {!isProcessing && step === 'NEW_PASSWORD' && !isInitialSetup && (
           <button type="button" onClick={() => setStep('AUTH')} className="w-full text-[11px] text-xmr-dim hover:text-xmr-green uppercase flex items-center justify-center gap-2 transition-colors cursor-pointer"><ArrowLeft size={12}/> Back to Unlock</button>
        )}
        {!isProcessing && step === 'RESTORE' && (
           <button type="button" onClick={() => setStep(isInitialSetup ? 'MODE' : 'AUTH')} className="w-full text-[11px] text-xmr-dim hover:text-xmr-green uppercase flex items-center justify-center gap-2 transition-colors cursor-pointer"><ArrowLeft size={12}/> {isInitialSetup ? 'Back' : 'Back to Unlock'}</button>
        )}
        {!isProcessing && step !== 'AUTH' && step !== 'NEW_PASSWORD' && step !== 'RESTORE' && (
           <button type="button" onClick={() => setStep(isInitialSetup ? 'MODE' : 'AUTH')} className="w-full text-[11px] text-xmr-dim hover:text-xmr-green uppercase flex items-center justify-center gap-2 transition-colors cursor-pointer"><ArrowLeft size={12}/> {isInitialSetup ? 'Back' : 'Back to Unlock'}</button>
        )}
      </div>
    </form>
  );
}
