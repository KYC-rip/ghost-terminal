import { useState, useEffect } from 'react';

export type ThemeMode = 'dark' | 'light' | 'system';
type ResolvedTheme = 'dark' | 'light';
type Contrast = 'default' | 'high';
export type Skin = 'terminal' | 'clean' | 'monero';

const SKIN_LABELS: Record<Skin, string> = {
  terminal: 'Terminal',
  clean: 'Clean',
  monero: 'Monero',
};

export function useTheme(forcedMode?: ThemeMode) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('theme-mode');
    return (saved === 'dark' || saved === 'light' || saved === 'system')
      ? (saved as ThemeMode)
      : 'dark'; // Desktop defaults to dark
  });

  const [contrast, setContrast] = useState<Contrast>(() => {
    const saved = localStorage.getItem('contrast');
    if (saved === 'high' || saved === 'default') return saved as Contrast;
    return 'default';
  });

  const [skin, setSkinState] = useState<Skin>(() => {
    const saved = localStorage.getItem('theme-skin');
    if (saved === 'terminal' || saved === 'clean' || saved === 'monero') return saved;
    return 'terminal';
  });

  const [resolvedTheme, setResolvedTheme] = useState<ResolvedTheme>('dark');

  // Theme state is shared by every local Tauri webview. Dedicated trusted
  // windows (VPN controls, confirmations) must follow changes made in the main
  // window instead of freezing whatever was current when they opened.
  useEffect(() => {
    const sync = (event: StorageEvent) => {
      if (event.storageArea !== localStorage) return;
      if (!forcedMode && event.key === 'theme-mode' && (event.newValue === 'dark' || event.newValue === 'light' || event.newValue === 'system')) {
        setModeState(event.newValue);
      } else if (event.key === 'contrast' && (event.newValue === 'high' || event.newValue === 'default')) {
        setContrast(event.newValue);
      } else if (event.key === 'theme-skin' && (event.newValue === 'terminal' || event.newValue === 'clean' || event.newValue === 'monero')) {
        setSkinState(event.newValue);
      }
    };
    window.addEventListener('storage', sync);
    return () => window.removeEventListener('storage', sync);
  }, [forcedMode]);

  useEffect(() => {
    const root = window.document.documentElement;
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

    const applyTheme = (targetTheme: ResolvedTheme) => {
      setResolvedTheme(targetTheme);
      root.classList.remove('light', 'dark');
      root.classList.add(targetTheme);
    };

    const appliedMode = forcedMode ?? mode;
    const handleSystemChange = () => {
      if (appliedMode === 'system') {
        applyTheme(mediaQuery.matches ? 'dark' : 'light');
      }
    };

    if (appliedMode === 'system') {
      applyTheme(mediaQuery.matches ? 'dark' : 'light');
      mediaQuery.addEventListener('change', handleSystemChange);
    } else {
      applyTheme(appliedMode);
    }

    if (!forcedMode) localStorage.setItem('theme-mode', mode);
    return () => mediaQuery.removeEventListener('change', handleSystemChange);
  }, [mode, forcedMode]);

  // Apply contrast
  useEffect(() => {
    const root = window.document.documentElement;
    root.classList.toggle('high-contrast', contrast === 'high');
    localStorage.setItem('contrast', contrast);
  }, [contrast]);

  // Apply skin
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('skin-terminal', 'skin-clean', 'skin-monero');
    root.classList.add(`skin-${skin}`);
    localStorage.setItem('theme-skin', skin);
  }, [skin]);

  const cycleTheme = () => {
    setModeState(prev => {
      if (prev === 'system') return 'light';
      if (prev === 'light') return 'dark';
      return 'system';
    });
  };

  const toggleContrast = () => setContrast(prev => prev === 'default' ? 'high' : 'default');

  const cycleSkin = () => {
    setSkinState(prev => prev === 'terminal' ? 'clean' : prev === 'clean' ? 'monero' : 'terminal');
  };

  return {
    mode, resolvedTheme, cycleTheme,
    contrast, toggleContrast,
    skin, skinLabel: SKIN_LABELS[skin], cycleSkin,
  };
}
