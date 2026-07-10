import { createContext, useContext, type ReactNode } from 'react';
import { useVigilEngine } from '../hooks/useVigilEngine';

/**
 * Hosts the single vigil engine instance ABOVE the lock gate so an armed
 * session survives lock/unlock cycles: the Kraken feed keeps ticking, SNIPE
 * executes fully while locked (the strike key and destination need no open
 * vault), and EJECT holds in PAUSED_LOCKED until unlock. The engine now
 * unmounts only on app quit — the persisted-session/re-arm path still covers
 * that. Exactly one armed session exists by construction (one provider).
 */

type VigilEngineApi = ReturnType<typeof useVigilEngine>;

const VigilContext = createContext<VigilEngineApi | null>(null);

export function VigilProvider({ children }: { children: ReactNode }) {
  const engine = useVigilEngine();
  return <VigilContext.Provider value={engine}>{children}</VigilContext.Provider>;
}

export function useVigil(): VigilEngineApi {
  const ctx = useContext(VigilContext);
  if (!ctx) throw new Error('useVigil must be used within VigilProvider');
  return ctx;
}
