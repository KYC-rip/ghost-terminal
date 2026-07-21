import type { MouseEvent } from 'react';
import { Copy, Check } from 'lucide-react';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';

interface AddressDisplayProps {
  address: string;
  className?: string;
  truncate?: boolean;
  length?: number;
  showCopyIndicator?: boolean;
}

/**
 * 🛰️ Tactical Address Formatter
 * Splits per 4 digits, separates by space, and makes the first char stronger.
 * Now with click-to-copy functionality.
 */
export function AddressDisplay({ address, className = '', truncate = false, length = 12, showCopyIndicator = false }: AddressDisplayProps) {
  const { copied, copy } = useCopyToClipboard();

  const handleCopy = (e: MouseEvent) => {
    e.stopPropagation();
    copy(address);
  };

  if (!address) return <span className="opacity-30 italic">WAITING_FOR_UPLINK...</span>;

  const raw = truncate ? address.substring(0, length) : address;
  const blocks = raw.match(/.{4}/g) || [raw];

  const leftOver = raw.replace(blocks.join(''), '');
  if (leftOver) blocks.push(leftOver);

  // Format each block
  const formattedBlocks = blocks.map((block, i) => {
    // First block: make first char strong
    const firstChar = block.charAt(0);
    const restOfBlock = block.substring(1);
    return (
      <span key={i} className="whitespace-nowrap">
        <span className="text-xmr-green font-bold">{firstChar}</span>
        <span className="text-xmr-green/60 font-normal">{restOfBlock}</span>
      </span>
    );
  });

  return (
    <div
      onClick={handleCopy}
      className={`group relative items-center gap-2 cursor-pointer transition-all active:scale-95 ${className}`}
      title="Click to Copy Full Address"
    >
      <code className={`font-mono flex flex-wrap gap-x-1 group-hover:opacity-80 transition-colors`}>
        {copied && <div className={`absolute flex items-center gap-1 transition-all duration-300 ${copied ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-2 pointer-events-none'}`}>
          <span className="text-xs font-black bg-xmr-green text-xmr-base px-1 rounded-sm leading-tight">COPIED</span>
          <Check size={10} className="text-xmr-green" />
        </div>}
        {formattedBlocks}
        {truncate && address.length > length && <span className="opacity-40">...</span>}
      </code>

      {/* Hover Icon (Hidden when copied) */}
      {!copied && showCopyIndicator && (
        <Copy
          size={10}
          className="opacity-0 group-hover:opacity-100 transition-opacity text-xmr-green shrink-0 absolute top-0 right-1 -translate-y-1/2"
        />
      )}
    </div>
  );
}
