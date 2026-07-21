import { useState, type Dispatch, type SetStateAction } from 'react';
import { Zap, ShieldCheck, Lock, Scale, FileText, Activity, ChevronDown, ChevronUp, Settings2 } from 'lucide-react';
import type { ComplianceLevel, ComplianceState } from '../services/swap';

interface Props {
  value: ComplianceState;
  onChange: (value: ComplianceState) => void | Dispatch<SetStateAction<ComplianceState>>;
  disabled?: boolean;
  className?: string;
  variant?: 'ghost' | 'vigil';
  defaultExpanded?: boolean;
}

export function ComplianceSelector({ 
  value, 
  onChange, 
  disabled = false, 
  className = '', 
  variant = 'ghost',
  defaultExpanded = false 
}: Props) {
  
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  // 1. Calculate color and text for summary state
  const getSummary = () => {
    if (value.kyc === 'STRICT' && value.log === 'STRICT') {
       return { label: 'MAX PRIVACY', color: variant === 'vigil' ? 'text-xmr-green border-xmr-green' : 'text-xmr-ghost border-xmr-ghost', bg: variant === 'vigil' ? 'bg-xmr-green/10' : 'bg-xmr-ghost/10' };
    }
    if (value.kyc === 'ANY' || value.log === 'ANY') {
       return { label: 'BEST RATE (RISK)', color: 'text-xmr-accent border-xmr-accent', bg: 'bg-xmr-accent/10' };
    }
    return { label: 'BALANCED', color: 'text-xmr-green border-xmr-green', bg: 'bg-xmr-green/10' };
  };

  const summary = getSummary();

  // 2. Render logic for a single selection row
  const renderRow = (
    type: 'kyc' | 'log', 
    currentLevel: ComplianceLevel, 
    onSelect: (l: ComplianceLevel) => void
  ) => {
    const isKyc = type === 'kyc';
    const label = isKyc ? 'KYC Risk Rating' : 'Log / Data Retention';
    const icon = isKyc ? <Scale size={12} /> : <FileText size={12} />;

    const activeStyles = {
      ANY: 'text-xmr-accent border-xmr-accent bg-xmr-accent/10 shadow-[0_0_10px_var(--color-xmr-accent)] shadow-xmr-accent/20',
      STANDARD: 'text-xmr-green border-xmr-green/50 bg-xmr-green/10 shadow-[0_0_10px_var(--color-xmr-green)] shadow-xmr-green/20',
      STRICT: variant === 'vigil' 
        ? 'text-xmr-green border-xmr-green bg-xmr-green/10 shadow-[0_0_10px_var(--color-xmr-green)] shadow-xmr-green/20'
        : 'text-xmr-ghost border-xmr-ghost bg-xmr-ghost/10 shadow-[0_0_15px_var(--color-xmr-ghost)] shadow-xmr-ghost/20'
    };

    // ✅ Modification 1: Responsive Padding (py-3 mobile, py-2 desktop) for touch-friendliness
    // ✅ Modification 2: Responsive Gap (gap-1 mobile, gap-2 desktop) to prevent wrapping on small screens
    const baseBtn = "relative flex items-center justify-center gap-1.5 md:gap-2 py-3 md:py-2 px-1 md:px-3 rounded-sm border transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex-1 font-mono text-[11px] font-bold tracking-wider";
    const inactiveBtn = "bg-xmr-base border-xmr-border text-xmr-dim opacity-60 hover:opacity-100 hover:border-xmr-dim/50 hover:bg-xmr-surface";

    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs uppercase tracking-wider text-xmr-dim/70 font-mono px-0.5">
           <span className="flex items-center gap-2">{icon} {label}</span>
           <div className="flex gap-1">
              <div className={`h-1.5 w-1.5 rounded-full transition-colors ${currentLevel === 'ANY' ? 'bg-xmr-accent' : 'bg-xmr-border'}`} />
              <div className={`h-1.5 w-1.5 rounded-full transition-colors ${currentLevel === 'STANDARD' ? 'bg-xmr-green' : 'bg-xmr-border'}`} />
              <div className={`h-1.5 w-1.5 rounded-full transition-colors ${currentLevel === 'STRICT' ? (variant === 'vigil' ? 'bg-xmr-green' : 'bg-xmr-ghost') : 'bg-xmr-border'}`} />
           </div>
        </div>
        <div className="flex gap-2">
           <button onClick={() => onSelect('ANY')} disabled={disabled} className={`${baseBtn} ${currentLevel === 'ANY' ? activeStyles.ANY : inactiveBtn}`}>
             <Zap size={12} className="shrink-0" />
             <span>ANY</span>
           </button>
           <button onClick={() => onSelect('STANDARD')} disabled={disabled} className={`${baseBtn} ${currentLevel === 'STANDARD' ? activeStyles.STANDARD : inactiveBtn}`}>
             <ShieldCheck size={12} className="shrink-0" />
             <span>STANDARD</span>
           </button>
           <button onClick={() => onSelect('STRICT')} disabled={disabled} className={`${baseBtn} ${currentLevel === 'STRICT' ? activeStyles.STRICT : inactiveBtn}`}>
             <Lock size={12} className="shrink-0" />
             <span>STRICT</span>
           </button>
        </div>
      </div>
    );
  };

  return (
    // ✅ Modification 3: Ensure w-full
    <div className={`w-full rounded-sm border border-xmr-border bg-xmr-surface/50 backdrop-blur-sm transition-all duration-300 overflow-hidden ${className} ${isExpanded ? 'p-2 md:p-4' : 'p-0 hover:border-xmr-dim/30'}`}>
      
      {/* 1. Header / Toggle Bar */}
      <button 
        onClick={() => !disabled && setIsExpanded(!isExpanded)}
        disabled={disabled}
        className={`w-full flex items-center justify-between gap-3 outline-none ${isExpanded ? 'mb-4 border-b border-xmr-border/50 pb-4' : 'p-4'}`}
      >
        <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-xmr-dim">
           <Settings2 size={14} className="shrink-0" />
           <span className="truncate">PRIVACY<span className='hidden md:inline'>_CONTROL</span></span>
        </div>

        <div className="flex items-center gap-2 md:gap-3 shrink-0">
           {/* Summary Badge */}
           <div className={`flex items-center gap-1.5 px-2 py-1 rounded-sm border text-[11px] font-mono font-bold whitespace-nowrap ${summary.color} ${summary.bg}`}>
              {summary.label === 'MAX PRIVACY' && <Lock size={10} className="shrink-0" />}
              {summary.label === 'BEST RATE (RISK)' && <Zap size={10} className="shrink-0" />}
              {summary.label === 'BALANCED' && <ShieldCheck size={10} className="shrink-0" />}
              <span>{summary.label}</span>
           </div>
           
           {/* Chevron */}
           <div className="text-xmr-dim/50">
              {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
           </div>
        </div>
      </button>

      {/* 2. Expandable Content */}
      {isExpanded && (
        <div className="space-y-5 md:space-y-4 animate-in slide-in-from-top-2 fade-in duration-300">
          
          {renderRow('kyc', value.kyc, (l) => onChange({ ...value, kyc: l }))}
          
          <div className="h-px w-full bg-xmr-border/50" />
          
          {renderRow('log', value.log, (l) => onChange({ ...value, log: l }))}

          <div className="text-[11px] font-mono text-center pt-1 min-h-[16px] text-xmr-dim flex flex-wrap items-center justify-center gap-2 opacity-80">
             <Activity size={10} />
             <span>
                API_FILTER :: 
                KYC[{value.kyc === 'STRICT' ? 'A' : value.kyc === 'STANDARD' ? 'B' : 'D'}] 
                // 
                LOG[{value.log === 'STRICT' ? 'A' : value.log === 'STANDARD' ? 'B' : 'C'}]
             </span>
          </div>
        </div>
      )}
    </div>
  );
}