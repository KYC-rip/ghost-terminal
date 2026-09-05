import { useState, useEffect, useRef } from 'react';
import { X, Tag, DollarSign, Copy, CheckCircle2, QrCode, ArrowDownToLine, Shuffle } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { useVault } from '../../contexts/VaultContext';
import { getOrCreateSubaddress } from '../../services/subaddressService';
import { useCopyToClipboard } from '../../hooks/useCopyToClipboard';

interface ExistingAddress {
  address: string;
  label: string;
  index: number;
}

interface ReceiveModalProps {
  onClose: () => void;
  existingAddress?: ExistingAddress;
  inline?: boolean;
}

export function ReceiveModal({ onClose, existingAddress, inline }: ReceiveModalProps) {
  const { createSubaddress, setSubaddressLabel, subaddresses } = useVault();
  const [tab, setTab] = useState<'direct' | 'cross'>('direct');

  // --- Unified Address State ---
  const [generatedAddress, setGeneratedAddress] = useState<string | null>(existingAddress?.address || null);
  const [generatedIndex, setGeneratedIndex] = useState<number | null>(existingAddress?.index ?? null);
  const [label, setLabel] = useState(existingAddress?.label || 'Payment_Request');
  const [isGenerating, setIsGenerating] = useState(false);
  const hasGeneratedRef = useRef(!!existingAddress);

  // --- Cross Chain State ---
  const [ccAmount, setCcAmount] = useState('');
  const [ccLink, setCcLink] = useState('');
  const { copied: ccCopied, copy: ccCopy } = useCopyToClipboard();
  const { copied: directCopied, copy: directCopy } = useCopyToClipboard();

  // Auto-generate or reuse subaddress on mount (skip if viewing existing)
  useEffect(() => {
    if (hasGeneratedRef.current) return;
    hasGeneratedRef.current = true;
    const gen = async () => {
      setIsGenerating(true);
      try {
        const addr = await getOrCreateSubaddress('Payment', subaddresses, createSubaddress);
        if (addr) setGeneratedAddress(addr);
      } catch (e) { console.error("Subaddress generation failed", e); }
      finally { setIsGenerating(false); }
    };
    gen();
  }, [createSubaddress, subaddresses]);

  // Resolve subaddress index for label updates
  useEffect(() => {
    if (generatedAddress && subaddresses && generatedIndex === null) {
      const found = subaddresses.find((s: any) => s.address === generatedAddress);
      if (found) setGeneratedIndex(found.index);
    }
  }, [generatedAddress, subaddresses, generatedIndex]);

  // Cross-Chain link — always XMR/mainnet, payer chooses their asset on the page
  useEffect(() => {
    if (!generatedAddress) { setCcLink(''); return; }
    const p = new URLSearchParams();
    p.set('source', 'pay');
    p.set('pay_to', generatedAddress.trim());
    if (ccAmount) p.set('amount', ccAmount);
    p.set('currency', 'xmr');
    p.set('network', 'mainnet');
    if (label) p.set('label', encodeURIComponent(label));
    setCcLink(`https://kyc.rip/swap?${p.toString()}`);
  }, [generatedAddress, ccAmount, label]);

  const handleLabelChange = (v: string) => {
    setLabel(v);
    if (generatedIndex !== null) setSubaddressLabel(generatedIndex, v || 'Payment_Request');
  };

  // Shared QR + Address display
  const AddressBlock = ({ qrValue, qrSize, imgSrc, imgSize, copyText, copied, onCopy, sublabel }: {
    qrValue: string; qrSize: number; imgSrc?: string; imgSize?: number;
    copyText: string; copied: boolean; onCopy: () => void; sublabel?: string;
  }) => (
    <div className="flex flex-col items-center gap-4">
      <div className="p-3 bg-white rounded-sm">
        <QRCodeSVG
          value={qrValue} size={qrSize} level="M" includeMargin={false}
          imageSettings={imgSrc ? { src: imgSrc, x: undefined, y: undefined, height: imgSize || 34, width: imgSize || 34, excavate: true } : undefined}
        />
      </div>
      {sublabel && <div className="text-[11px] text-xmr-dim uppercase tracking-widest">{sublabel}</div>}
      <div
        onClick={onCopy}
        className="w-full bg-xmr-base border border-xmr-border p-3 text-[11px] font-mono text-xmr-green break-all cursor-pointer hover:border-xmr-green transition-colors relative group"
      >
        {copyText}
        <span className="absolute right-3 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity text-xmr-green">
          {copied ? <CheckCircle2 size={14} /> : <Copy size={14} />}
        </span>
      </div>
      {copied && <div className="text-[11px] text-xmr-green animate-pulse uppercase tracking-widest">Copied!</div>}
    </div>
  );

  const content = (
      <div className={`w-full ${inline ? '' : 'max-w-xl bg-xmr-surface border border-xmr-border rounded-sm'} relative flex flex-col ${inline ? 'h-full' : 'max-h-[85vh]'} overflow-hidden`}>

        {/* Header — matches tab bar style when inline */}
        <div className={`flex items-center justify-between ${inline ? 'px-3 py-2 bg-xmr-surface/50' : 'px-6 py-4'} border-b border-xmr-border/${inline ? '15' : '40'}`}>
          <div className="flex gap-1 items-center">
            {([
              { id: 'direct' as const, label: 'Direct XMR', icon: <ArrowDownToLine size={12} /> },
              { id: 'cross' as const, label: 'Payment Link', icon: <Shuffle size={12} /> },
            ]).map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`px-4 py-2 text-[11px] font-black uppercase tracking-widest transition-all rounded-sm flex items-center gap-1.5 cursor-pointer ${tab === t.id
                    ? 'text-xmr-green border border-xmr-green/30 bg-xmr-green/5'
                    : 'text-xmr-dim hover:text-xmr-green border border-transparent'
                  }`}
              >
                {t.icon} {t.label}
              </button>
            ))}
          </div>
          <button onClick={onClose} className="text-xmr-dim hover:text-xmr-green transition-colors cursor-pointer p-1"><X size={20} /></button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-5">

          {isGenerating ? (
            <div className="py-16 flex flex-col items-center justify-center gap-3 text-xmr-green/60 animate-pulse">
              <QrCode size={40} />
              <span className="text-[11px] uppercase font-mono tracking-widest">Generating subaddress...</span>
            </div>
          ) : (
            <>
              {/* Label */}
              <div className="space-y-1.5">
                <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
                  <Tag size={10} /> Label
                </label>
                <input
                  type="text" value={label}
                  onChange={(e) => handleLabelChange(e.target.value)}
                  placeholder="Payment_Request"
                  className="w-full bg-xmr-base border border-xmr-border p-2.5 text-xs text-xmr-green focus:border-xmr-green outline-none transition-colors"
                />
              </div>

              {/* ════════ DIRECT XMR ════════ */}
              {tab === 'direct' && generatedAddress && (
                <AddressBlock
                  qrValue={`monero:${generatedAddress}`}
                  qrSize={180}
                  imgSrc="/monero-xmr-logo.png"
                  imgSize={40}
                  copyText={generatedAddress}
                  copied={directCopied}
                  onCopy={() => directCopy(generatedAddress)}
                  sublabel="Scan or copy subaddress"
                />
              )}

              {/* ════════ PAYMENT LINK ════════ */}
              {tab === 'cross' && (
                <div className="space-y-5">
                  <div className="space-y-1.5">
                    <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
                      <DollarSign size={10} /> Expected Amount <span className="opacity-50">(Optional)</span>
                    </label>
                    <input
                      type="number" value={ccAmount}
                      onChange={(e) => setCcAmount(e.target.value)}
                      placeholder="Amount in XMR"
                      className="w-full bg-xmr-base border border-xmr-border p-2.5 text-xs focus:border-xmr-green outline-none text-xmr-green"
                    />
                  </div>
                  <AddressBlock
                    qrValue={ccLink || 'https://kyc.rip'}
                    qrSize={180}
                    imgSrc="/monero-xmr-logo.png"
                    imgSize={40}
                    copyText={ccLink || 'Generating link...'}
                    copied={ccCopied}
                    onCopy={() => ccLink && ccCopy(ccLink)}
                    sublabel={ccLink ? 'Payer chooses their asset on kyc.rip' : undefined}
                  />
                </div>
              )}
            </>
          )}
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
