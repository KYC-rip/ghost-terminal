import { useState, useEffect, useRef } from 'react';
import { RefreshCw, Key, Send, Download, Wind, Loader2, Edit2, Scissors, MoreVertical, Plus, ChevronLeft, ChevronRight } from 'lucide-react';
import { AddressBook } from './vault/AddressBook';
import { AddressList } from './vault/AddressList';
import { CoinControl } from './vault/CoinControl';
import { TransactionLedger } from './vault/TransactionLedger';
import { VaultModals } from './vault/VaultModals';
import { DispatchModal } from './vault/DispatchModal';
import { ReceiveModal } from './vault/ReceiveModal';
import { type VaultContextType } from '../contexts/VaultContext';
import { WalletService } from '../services/walletService';
import { useFiatValue } from '../hooks/useFiatValue';
import { FaucetCard } from './vault/FaucetCard';
import { isStressnet } from '../utils/networkMode';

interface VaultViewProps {
  setView: (v: any) => void;
  vault: VaultContextType;
  handleBurn: () => void;
  appConfig: any;
}

export function VaultView({ setView, vault, handleBurn, appConfig }: VaultViewProps) {
  const {
    accounts, selectedAccountIndex, setSelectedAccountIndex,
    balance, address, subaddresses, outputs, refresh,
    status, isSending, sendXmr, createSubaddress,
    churn, splinter, txs, currentHeight, totalHeight, syncPercent, activeId, setSubaddressLabel,
    vanishSubaddress, requestedAction
  } = vault;
  const [tab, setTab] = useState<'ledger' | 'addresses' | 'coins' | 'contacts'>('ledger');
  const [modals, setModals] = useState({ seed: false, receive: false, send: false, splinter: false, churn: false });
  const [mnemonic, setMnemonic] = useState('');
  const [contacts, setContacts] = useState<any[]>([]);
  const [dispatchAddr, setDispatchAddr] = useState('');
  const [selectedSubaddress, setSelectedSubaddress] = useState<any>(null);
  const [dispatchSubIndex, setDispatchSubIndex] = useState<number | undefined>(undefined);
  const [showCardMenu, setShowCardMenu] = useState(false);
  const [showAccountList, setShowAccountList] = useState(false);
  const [editingAccountId, setEditingAccountId] = useState<number | null>(null);
  const [editAccountName, setEditAccountName] = useState('');
  const [hideZeroBalances, setHideZeroBalances] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [activePanel, setActivePanel] = useState<'send' | 'receive' | null>(null);

  const currentAcc = accounts.find(a => a.index === selectedAccountIndex);
  const currentAccBalance = currentAcc?.balance || '0.0000';
  const { fiatText: usdValue } = useFiatValue('XMR', currentAccBalance, true);

  useEffect(() => {
    const loadAddressBook = async () => {
      const bookKey = `address_book_${activeId}` as keyof typeof appConfig;
      setContacts((appConfig as any)[bookKey] || []);
      setHideZeroBalances(!!appConfig.hide_zero_balances);
    };
    if (appConfig) loadAddressBook();
  }, [activeId, appConfig]);

  const cardMenuRef = useRef<HTMLDivElement>(null);
  const accountListRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (requestedAction) {
      if (requestedAction === 'OPEN_SEND') setActivePanel('send');
      else if (requestedAction === 'OPEN_RECEIVE') setActivePanel('receive');
      else if (requestedAction === 'OPEN_CHURN') setModals(prev => ({ ...prev, churn: true }));
      else if (requestedAction === 'OPEN_SPLINTER') setModals(prev => ({ ...prev, splinter: true }));
      vault.setRequestedAction(null);
    }
  }, [requestedAction, vault]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (cardMenuRef.current && !cardMenuRef.current.contains(event.target as Node)) {
        setShowCardMenu(false);
      }
      if (accountListRef.current && !accountListRef.current.contains(event.target as Node)) {
        setShowAccountList(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Card switch animation
  useEffect(() => {
    setSwitching(true);
    const t = setTimeout(() => setSwitching(false), 150);
    return () => clearTimeout(t);
  }, [selectedAccountIndex]);

  const saveContacts = async (updated: any[]) => {
    setContacts(updated);
    const currentConfig = await window.api.getConfig();
    await window.api.saveConfigAndReload({
      ...currentConfig,
      [`address_book_${activeId}`]: updated
    });
  };

  const handleOpenCreateModal = async () => {
    const label = prompt("ENTER_ACCOUNT_LABEL:", "Savings_Account");

    if (label) {
      try {
        const res = await WalletService.createAccount(label);

        if (res.address) {
          await refresh();
          setSelectedAccountIndex(res.index);
        }
      } catch (e: any) {
        alert(`ACCOUNT_CREATION_FAILED: ${e.message}`);
      }
    }
  };

  const revealSeed = async () => {
    if (!confirm("⚠️ SECURITY WARNING ⚠️\n\nReveal Master Seed?\nEnsure no cameras or screen recording software is active.")) return;

    try {
      const res = await window.api.walletAction('mnemonic');
      if (res.success && res.seed) {
        setMnemonic(res.seed);
        setModals(prev => ({ ...prev, seed: true }));
      } else {
        alert(`SEED_RETRIEVAL_FAILED: ${res.error || 'Wallet may still be syncing. Try again in a moment.'}`);
      }
    } catch (e: any) {
      alert(`RPC_ERROR: ${e.message || 'Could not retrieve mnemonic. Wallet may be busy syncing.'}`);
    }
  };

  const handleToggleFilter = async (val: boolean) => {
    setHideZeroBalances(val);
    const updatedConfig = { ...appConfig, hide_zero_balances: val };
    await window.api.saveConfigOnly?.(updatedConfig) || await window.api.saveConfigAndReload(updatedConfig);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const isSyncing = status === 'SYNCING' || status === 'READY';
  const blocksLeft = totalHeight > 0 && currentHeight > 0 ? totalHeight - currentHeight : 0;
  // Only block actions for large syncs (>1000 blocks ≈ 1.4 days behind)
  // Small gaps (<1000 blocks) catch up in seconds — no need to lock the UI
  const isHeavySync = isSyncing && blocksLeft > 1000;

  const currentAccIdx = accounts.findIndex(a => a.index === selectedAccountIndex);
  const prevAccount = () => {
    if (accounts.length <= 1) return;
    const prevIdx = (currentAccIdx - 1 + accounts.length) % accounts.length;
    setSelectedAccountIndex(accounts[prevIdx].index);
  };
  const nextAccount = () => {
    if (accounts.length <= 1) return;
    const nextIdx = (currentAccIdx + 1) % accounts.length;
    setSelectedAccountIndex(accounts[nextIdx].index);
  };

  const hasNoBalance = parseFloat(currentAcc?.unlockedBalance || '0') <= 0;
  const totalBalance = accounts.reduce((sum, acc) => sum + parseFloat(acc.balance || '0'), 0);
  const totalUnlocked = accounts.reduce((sum, acc) => sum + parseFloat(acc.unlockedBalance || '0'), 0);
  const { fiatText: totalFiat } = useFiatValue('XMR', totalBalance.toFixed(12), true);

  const quickActions = [
    { label: 'Dispatch', icon: Send, onClick: () => setActivePanel('send'), disabled: isHeavySync },
    { label: 'Receive', icon: Download, onClick: () => setActivePanel('receive'), disabled: isHeavySync },
    { label: 'Churn', icon: Wind, onClick: () => setModals(prev => ({ ...prev, churn: true })), disabled: isHeavySync || isSending || hasNoBalance },
    { label: 'Splinter', icon: Scissors, onClick: () => setModals(prev => ({ ...prev, splinter: true })), disabled: isHeavySync || isSending || hasNoBalance },
    { label: 'Sync', icon: RefreshCw, onClick: refresh, disabled: false, spin: isSyncing || isSending },
  ];

  return (
    <div className="max-w-6xl mx-auto space-y-6 py-2 pt-0 animate-in fade-in zoom-in-95 duration-300 font-black relative">

      {/* STRESSNET FAUCET — empty test wallets get one obvious action */}
      {isStressnet() && totalBalance <= 0 && <FaucetCard address={address} />}

      {/* SYNC STATUS BANNER — only for heavy syncs (>1000 blocks behind) */}
      {isHeavySync && (
        <div className="flex items-center gap-3 px-4 py-3 bg-xmr-accent/10 border border-xmr-accent/30 rounded-sm animate-pulse">
          <Loader2 size={14} className="text-xmr-accent animate-spin shrink-0" />
          <span className="text-xs font-black text-xmr-accent uppercase tracking-widest leading-relaxed">
            Synchronizing_Ledger... Height: {currentHeight || '---'}
            {blocksLeft > 0 ? ` ( ${blocksLeft} BLOCKS LEFT : ${syncPercent?.toFixed(2)}% )` : ''}
            — Send/Receive disabled until sync completes
          </span>
        </div>
      )}

      {/* 2. ACCOUNT CARD + QUICK ACTIONS */}
      <div className="relative z-10 font-black font-mono space-y-4">

        {/* Full-width account card */}
        <div className="relative" style={{ perspective: '800px' }}>
          {/* Background cards (stack effect) */}
          {accounts.length >= 3 && (
            <div className="absolute top-0 left-8 right-8 h-full bg-xmr-surface border border-xmr-border/15 rounded-sm" style={{ transform: 'translateY(-6px) scale(0.96)', opacity: 0.25 }} />
          )}
          {accounts.length >= 2 && (
            <div className="absolute top-0 left-4 right-4 h-full bg-xmr-surface border border-xmr-border/20 rounded-sm" style={{ transform: 'translateY(-3px) scale(0.98)', opacity: 0.4 }} />
          )}

          {/* Main card */}
          <div className={`relative bg-gradient-to-br from-xmr-green/5 via-xmr-green/8 to-xmr-green/3 bg-xmr-surface border border-xmr-green/40 rounded-sm shadow-[0_8px_32px_rgba(0,0,0,0.5)] transition-all duration-150 ${switching ? 'opacity-70 scale-[0.99]' : 'opacity-100 scale-100'}`}>
            {/* Top glow */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-xmr-green/50 to-transparent rounded-t-sm" />
            {/* Watermark */}
            <div className="absolute right-6 bottom-3 text-8xl font-black text-xmr-green/[0.03] tracking-tighter select-none pointer-events-none">XMR</div>

            {/* Card content: 2-column layout inside */}
            <div className="flex relative z-10">
              {/* Left: account info + balance */}
              <div className="flex-1 p-6 pr-0">
                {/* Header row */}
                <div className="flex items-start gap-3 mb-4">
                  {/* Prev arrow */}
                  {accounts.length > 1 && (
                    <button onClick={prevAccount} className="mt-0.5 w-7 h-7 flex items-center justify-center rounded-full border border-xmr-border/30 text-xmr-dim hover:text-xmr-green hover:border-xmr-green/50 hover:bg-xmr-green/10 transition-all cursor-pointer shrink-0">
                      <ChevronLeft size={14} />
                    </button>
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] text-xmr-dim font-bold tracking-[0.2em] uppercase">ACCT #{String(selectedAccountIndex).padStart(2, '0')}</div>
                    {editingAccountId === selectedAccountIndex ? (
                      <input
                        autoFocus
                        value={editAccountName}
                        onChange={(e) => setEditAccountName(e.target.value)}
                        onBlur={async () => {
                          if (editAccountName.trim() && editAccountName !== currentAcc?.label) {
                            await vault.renameAccount(selectedAccountIndex, editAccountName.trim());
                          }
                          setEditingAccountId(null);
                        }}
                        onKeyDown={async (e) => {
                          if (e.key === 'Enter') {
                            if (editAccountName.trim() && editAccountName !== currentAcc?.label) {
                              await vault.renameAccount(selectedAccountIndex, editAccountName.trim());
                            }
                            setEditingAccountId(null);
                          } else if (e.key === 'Escape') {
                            setEditingAccountId(null);
                          }
                        }}
                        className="bg-xmr-base border border-xmr-green text-xmr-green text-sm font-black p-1 uppercase outline-none mt-0.5 w-48"
                      />
                    ) : (
                      <div className="text-base font-black uppercase tracking-[0.15em] text-xmr-green mt-0.5 truncate">
                        {currentAcc?.label || 'UNTITLED_ACCOUNT'}
                      </div>
                    )}
                  </div>
                  {/* Next arrow */}
                  {accounts.length > 1 && (
                    <button onClick={nextAccount} className="mt-0.5 w-7 h-7 flex items-center justify-center rounded-full border border-xmr-border/30 text-xmr-dim hover:text-xmr-green hover:border-xmr-green/50 hover:bg-xmr-green/10 transition-all cursor-pointer shrink-0">
                      <ChevronRight size={14} />
                    </button>
                  )}
                  {/* Three-dot menu */}
                  <div className="relative shrink-0" ref={cardMenuRef}>
                    <button
                      onClick={() => setShowCardMenu(!showCardMenu)}
                      className="w-7 h-7 flex items-center justify-center border border-xmr-border/20 rounded-sm text-xmr-dim hover:text-xmr-green hover:border-xmr-green/50 hover:bg-xmr-green/10 transition-all cursor-pointer"
                    >
                      <MoreVertical size={14} />
                    </button>
                    {showCardMenu && (
                      <div className="absolute right-0 top-9 bg-xmr-base border border-xmr-border/50 rounded-sm shadow-xl z-50 min-w-[180px] py-1 animate-in fade-in zoom-in-95 duration-150">
                        <button
                          onClick={() => { setEditAccountName(currentAcc?.label || ''); setEditingAccountId(selectedAccountIndex); setShowCardMenu(false); }}
                          className="w-full px-4 py-2.5 text-left text-[11px] font-black uppercase tracking-widest text-xmr-dim hover:text-xmr-green hover:bg-xmr-green/10 transition-all flex items-center gap-2 cursor-pointer"
                        >
                          <Edit2 size={10} /> Rename
                        </button>
                        <button
                          onClick={() => { handleOpenCreateModal(); setShowCardMenu(false); }}
                          className="w-full px-4 py-2.5 text-left text-[11px] font-black uppercase tracking-widest text-xmr-accent hover:bg-xmr-accent/10 transition-all flex items-center gap-2 cursor-pointer"
                        >
                          <Plus size={10} /> New Account
                        </button>
                        <div className="border-t border-xmr-border/20 my-1" />
                        <button
                          onClick={() => { revealSeed(); setShowCardMenu(false); }}
                          className="w-full px-4 py-2.5 text-left text-[11px] font-black uppercase tracking-widest text-xmr-dim hover:text-xmr-accent hover:bg-xmr-accent/10 transition-all flex items-center gap-2 cursor-pointer"
                        >
                          <Key size={10} /> Backup Seed
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Balance */}
                <div className="flex items-baseline gap-2.5 mb-1">
                  <span className="text-4xl font-black text-xmr-green leading-none" style={{ fontFamily: 'var(--font-display)' }}>{currentAccBalance}</span>
                  <span className="text-sm text-xmr-dim font-medium" style={{ fontFamily: 'var(--font-display)' }}>XMR</span>
                </div>
                {usdValue && (
                  <div className="text-xs font-bold text-xmr-dim/60 uppercase tracking-[0.1em] mb-2">{usdValue} USD</div>
                )}

                {/* Address */}
                <div className="text-[10px] text-xmr-dim/30 tracking-wider mb-3">
                  {currentAcc?.baseAddress?.substring(0, 12)}...{currentAcc?.baseAddress?.substring((currentAcc?.baseAddress?.length || 8) - 8)}
                </div>

                {/* Quick Actions — inline in card */}
                <div className="flex gap-2 flex-wrap">
                  {quickActions.map(action => (
                    <button
                      key={action.label}
                      onClick={action.onClick}
                      disabled={action.disabled}
                      className="flex items-center gap-2 px-4 py-2 rounded-sm border border-xmr-green/20 bg-xmr-base/40 text-xmr-green hover:border-xmr-green/50 hover:bg-xmr-green/10 transition-all cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed group"
                    >
                      <action.icon size={14} className={action.spin ? 'animate-spin' : ''} />
                      <span className="text-[9px] font-bold uppercase tracking-[0.12em] group-hover:text-xmr-green transition-colors">
                        {action.label}
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Right: portfolio summary + status */}
              <div className="w-[280px] shrink-0 border-l border-xmr-border/15 p-5 flex flex-col justify-between">
                {/* Portfolio total */}
                <div>
                  <div className="text-[9px] font-black uppercase tracking-widest text-xmr-dim/60 mb-1">Portfolio ({accounts.length} accts)</div>
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-xl font-black text-xmr-green" style={{ fontFamily: 'var(--font-display)' }}>{totalBalance.toFixed(4)}</span>
                    <span className="text-[10px] text-xmr-dim font-bold">XMR</span>
                  </div>
                  {totalFiat && <div className="text-[10px] font-bold text-xmr-dim/40 uppercase tracking-wider">{totalFiat} USD</div>}
                </div>

                {/* Status rows */}
                <div className="space-y-1 mt-3 pt-3 border-t border-xmr-border/15">
                  <div className="flex justify-between text-[10px] uppercase font-black">
                    <span className="text-xmr-dim/40">Uplink:</span>
                    <span className={`flex items-center gap-1 ${isSyncing ? 'text-xmr-accent' : 'text-xmr-green'}`}>
                      {isSyncing && <Loader2 size={8} className="animate-spin" />}
                      {status}
                    </span>
                  </div>
                  <div className="flex justify-between text-[10px] uppercase font-black">
                    <span className="text-xmr-dim/40">Height:</span>
                    <span className="text-xmr-green">{currentHeight || '---'}</span>
                  </div>
                  <div className="flex justify-between text-[10px] uppercase font-black">
                    <span className="text-xmr-dim/40">Unlocked:</span>
                    <span className="text-xmr-green">{parseFloat(currentAcc?.unlockedBalance || '0').toFixed(4)}</span>
                  </div>
                  <div className="flex justify-between text-[10px] uppercase font-black">
                    <span className="text-xmr-dim/40">Outputs:</span>
                    <span className="text-xmr-green">{outputs?.length || 0}</span>
                  </div>
                </div>

                {/* All accounts trigger */}
                <div className="relative mt-3 pt-3 border-t border-xmr-border/15" ref={accountListRef}>
                  <button
                    onClick={() => setShowAccountList(!showAccountList)}
                    className="w-full flex items-center justify-between text-[10px] font-black text-xmr-dim hover:text-xmr-green transition-colors cursor-pointer uppercase tracking-widest px-2.5 py-1.5 border border-xmr-border/20 rounded-sm hover:border-xmr-green/40"
                  >
                    <span>All Accounts</span>
                    <span className="text-xmr-green/60">{currentAccIdx + 1}/{accounts.length}</span>
                  </button>
                  {showAccountList && (
                    <div className="absolute bottom-10 right-0 bg-xmr-base border border-xmr-border/50 rounded-sm shadow-2xl z-50 w-[340px] max-h-[400px] flex flex-col animate-in fade-in slide-in-from-bottom-2 duration-150">
                      <div className="px-4 py-3 border-b border-xmr-border/30 bg-xmr-green/5">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-[10px] font-black uppercase tracking-widest text-xmr-dim">All Accounts ({accounts.length})</span>
                          <span className="text-[10px] font-black uppercase tracking-widest text-xmr-dim">Total</span>
                        </div>
                        <div className="flex justify-between items-baseline">
                          <span className="text-[10px] text-xmr-dim/50 uppercase tracking-wider">Unlocked: {totalUnlocked.toFixed(4)}</span>
                          <div className="text-right">
                            <span className="text-sm font-black text-xmr-green">{totalBalance.toFixed(4)} XMR</span>
                            {totalFiat && <div className="text-[10px] text-xmr-dim/60 font-bold">{totalFiat} USD</div>}
                          </div>
                        </div>
                      </div>
                      <div className="overflow-y-auto custom-scrollbar flex-1">
                        {accounts.map(acc => (
                          <button
                            key={acc.index}
                            onClick={() => { setSelectedAccountIndex(acc.index); setShowAccountList(false); }}
                            className={`w-full px-4 py-2.5 flex items-center justify-between text-left transition-all cursor-pointer hover:bg-xmr-green/10 border-b border-xmr-border/10 ${acc.index === selectedAccountIndex ? 'bg-xmr-green/5 border-l-2 border-l-xmr-green' : ''}`}
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <span className="text-[10px] text-xmr-dim font-bold shrink-0 w-6">{String(acc.index).padStart(2, '0')}</span>
                              <span className="text-[11px] text-xmr-green font-black uppercase truncate">{acc.label || 'UNTITLED'}</span>
                            </div>
                            <div className="text-right shrink-0 ml-3">
                              <div className="text-[11px] text-xmr-green font-bold">{parseFloat(acc.balance).toFixed(4)}</div>
                              <div className="text-[9px] text-xmr-dim/50 font-bold">XMR</div>
                            </div>
                          </button>
                        ))}
                      </div>
                      <button
                        onClick={() => { handleOpenCreateModal(); setShowAccountList(false); }}
                        className="px-4 py-2.5 text-center text-[10px] text-xmr-accent font-black uppercase tracking-widest hover:bg-xmr-accent/10 transition-all cursor-pointer border-t border-xmr-border/30 shrink-0"
                      >
                        + New Account
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>

          </div>
        </div>

      </div>

      {/* 3. TABS + CONTENT (or inline Send/Receive panel) */}
      <div className="min-h-[400px] border border-xmr-border/20 rounded-sm overflow-hidden bg-xmr-surface/30">
        {activePanel === 'send' ? (
          <DispatchModal
            inline
            onClose={() => { setActivePanel(null); setDispatchSubIndex(undefined); }}
            initialAddress={dispatchAddr}
            sourceSubaddressIndex={dispatchSubIndex}
          />
        ) : activePanel === 'receive' ? (
          <ReceiveModal
            inline
            onClose={() => { setActivePanel(null); setSelectedSubaddress(null); }}
            existingAddress={selectedSubaddress || undefined}
          />
        ) : (
          <>
            {/* Tab bar */}
            <div className="flex gap-1 items-center px-3 py-2 border-b border-xmr-border/15 bg-xmr-surface/50">
              {['ledger', 'coins', 'addresses', 'contacts'].map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t as any)}
                  className={`px-4 py-2 text-[11px] font-black uppercase tracking-widest transition-all rounded-sm ${tab === t ? 'text-xmr-green border border-xmr-green/30 bg-xmr-green/5' : 'text-xmr-dim hover:text-xmr-green border border-transparent'}`}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div>
              {tab === 'ledger' && <TransactionLedger txs={txs} subaddresses={subaddresses} />}
              {tab === 'coins' && <CoinControl outputs={outputs} onSendFromCoin={(_keyImage, _amount) => { setActivePanel('send'); }} />}
              {tab === 'addresses' && <AddressList
                subaddresses={hideZeroBalances ? subaddresses.filter(s => parseFloat(s.balance) > 0 || s.index === 0) : subaddresses}
                handleCopy={handleCopy}
                onUpdateLabel={setSubaddressLabel}
                onRowClick={(s) => { setSelectedSubaddress(s); setActivePanel('receive'); }}
                onVanishSubaddress={vanishSubaddress}
                onSendFrom={(idx) => { setDispatchSubIndex(idx); setActivePanel('send'); }}
                isSyncing={status === 'SYNCING'}
                hideZeroBalances={hideZeroBalances}
                onToggleFilter={handleToggleFilter}
              />}
              {tab === 'contacts' && <AddressBook
                contacts={contacts}
                onAddContact={(c) => saveContacts([...contacts, c])}
                onRemoveContact={(idx) => saveContacts(contacts.filter((_, i) => i !== idx))}
                onDispatch={(addr) => { setDispatchAddr(addr); setActivePanel('send'); }}
                handleCopy={handleCopy}
              />}
            </div>
          </>
        )}
      </div>

      {/* 5. MODALS */}
      <VaultModals
        showSeed={modals.seed}
        onCloseSeed={() => setModals(prev => ({ ...prev, seed: false }))}
        mnemonic={mnemonic}
        showReceive={modals.receive}
        onCloseReceive={() => { setModals(prev => ({ ...prev, receive: false })); setSelectedSubaddress(null); }}
        onCreateSub={createSubaddress}
        selectedSubaddress={selectedSubaddress}
        showSend={modals.send}
        onCloseSend={() => { setModals(prev => ({ ...prev, send: false })); setDispatchSubIndex(undefined); }}
        onSend={sendXmr}
        isSending={isSending}
        initialAddr={dispatchAddr}
        sourceSubaddressIndex={dispatchSubIndex}
        showSplinter={modals.splinter}
        onCloseSplinter={() => setModals(prev => ({ ...prev, splinter: false }))}
        onSplinter={splinter}
        showChurn={modals.churn}
        onCloseChurn={() => setModals(prev => ({ ...prev, churn: false }))}
        onChurn={churn}
        unlockedBalance={parseFloat(currentAcc?.unlockedBalance || '0')}
      />
    </div>
  );
}
