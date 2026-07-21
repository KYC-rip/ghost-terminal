import type { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  noPadding?: boolean;
  withGlow?: boolean; 
  topGradientAccentColor?: 'xmr-green' | 'xmr-ghost' | 'xmr-warning' | 'xmr-accent' | 'xmr-dim' | 'xmr-error';
}

const GRADIENT_MAP = {
  'xmr-green': 'from-xmr-green/0 via-xmr-green/50 to-xmr-green/0',
  'xmr-ghost': 'from-xmr-ghost/0 via-xmr-ghost/50 to-xmr-ghost/0',
  'xmr-warning': 'from-xmr-warning/0 via-xmr-warning/50 to-xmr-warning/0',
  'xmr-accent': 'from-xmr-accent/0 via-xmr-accent/50 to-xmr-accent/0',
  'xmr-dim': 'from-xmr-dim/0 via-xmr-dim/50 to-xmr-dim/0',
  'xmr-error': 'from-xmr-error/0 via-xmr-error/50 to-xmr-error/0',
};

export function Card({ 
  children, 
  className = '', 
  noPadding = false,
  withGlow = true,
  topGradientAccentColor = 'xmr-green'
}: CardProps) {
  const gradientClass = GRADIENT_MAP[topGradientAccentColor] || GRADIENT_MAP['xmr-green'];
  const borderClass = `border-${topGradientAccentColor}/50`;

  return (
    <div className={`
      bg-xmr-surface border shadow-lg relative overflow-hidden group rounded-sm
      ${borderClass}
      ${noPadding ? '' : 'p-6'}
      ${className}
    `}>
      {/* Top Gradient Accent (Cyberpunk Glow Effect) */}
      {withGlow && (
        <div className={`absolute top-0 left-0 w-full h-1 bg-gradient-to-r ${gradientClass} opacity-50 group-hover:opacity-80 transition-opacity duration-500`}></div>
      )}
      
      {children}
    </div>
  );
}