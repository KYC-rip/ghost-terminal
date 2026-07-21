import { useState } from 'react';
import { Book, PlusCircle, X } from 'lucide-react';
import { Card } from '../Card';
import { TableHeader } from './TableHeader';

interface AddressBookProps {
  contacts: any[];
  onAddContact: (contact: { name: string; address: string }) => void;
  onRemoveContact: (index: number) => void;
  onDispatch: (address: string) => void;
  handleCopy: (text: string) => void;
}

export function AddressBook({ contacts, onAddContact, onRemoveContact, onDispatch, handleCopy }: AddressBookProps) {
  const [showAdd, setShowAdd] = useState(false);
  const [newContact, setNewContact] = useState({ name: '', address: '' });

  return (
    <>
      <Card noPadding className="h-[400px] flex flex-col">
        <TableHeader>
          <span>Address_Book</span>
          <button onClick={() => setShowAdd(true)} className="flex items-center gap-1 text-xmr-green hover:underline cursor-pointer">
            <PlusCircle size={10}/> ADD_NEW
          </button>
        </TableHeader>
        <div className="flex-grow overflow-y-auto custom-scrollbar">
          {contacts.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
              {contacts.map((c, i) => (
                <div key={i} className="p-4 border border-xmr-border/20 bg-xmr-green/[0.02] flex flex-col gap-3 relative group">
                  <button 
                    onClick={() => onRemoveContact(i)} 
                    className="absolute top-2 right-2 text-xmr-error/40 opacity-0 group-hover:opacity-100 transition-all hover:text-xmr-error cursor-pointer"
                  >
                    <X size={12}/>
                  </button>
                  <div className="flex items-center gap-2">
                    <Book size={14} className="text-xmr-green"/>
                    <span className="text-xs font-black text-xmr-green uppercase">{c.name}</span>
                  </div>
                  <code className="text-[11px] opacity-40 break-all leading-tight italic">{c.address}</code>
                  <div className="flex gap-2">
                    <button onClick={() => handleCopy(c.address)} className="flex-1 py-1.5 border border-xmr-border/30 text-xs hover:bg-xmr-green/10 transition-all uppercase cursor-pointer">Copy</button>
                    <button onClick={() => onDispatch(c.address)} className="flex-1 py-1.5 bg-xmr-green/10 border border-xmr-green/30 text-xmr-green text-xs hover:bg-xmr-green/20 transition-all uppercase cursor-pointer">Dispatch</button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center gap-4 opacity-20">
              <Book size={48} />
              <span className="text-xs font-black uppercase">Your address book is empty</span>
            </div>
          )}
        </div>
      </Card>

      {/* ADD CONTACT MODAL */}
      {showAdd && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-6 bg-xmr-base/95 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-md space-y-6">
            <h3 className="text-xl font-black text-xmr-green uppercase italic text-center">New_Contact_Archived</h3>
            <Card className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-[11px] font-black text-xmr-dim uppercase ml-1">Alias_Name</label>
                <input 
                  type="text" 
                  value={newContact.name} 
                  onChange={(e) => setNewContact({...newContact, name: e.target.value})} 
                  placeholder="Tactical_Alias" 
                  className="w-full bg-xmr-base border border-xmr-border p-3 text-[11px] text-xmr-green outline-none" 
                />
              </div>
              <div className="space-y-1">
                <label className="text-[11px] font-black text-xmr-dim uppercase ml-1">Monero_Address</label>
                <input 
                  type="text" 
                  value={newContact.address} 
                  onChange={(e) => setNewContact({...newContact, address: e.target.value})} 
                  placeholder="4... / 8..." 
                  className="w-full bg-xmr-base border border-xmr-border p-3 text-[11px] text-xmr-green outline-none" 
                />
              </div>
              <div className="flex gap-3">
                <button onClick={() => setShowAdd(false)} className="flex-1 py-3 border border-xmr-border text-xmr-dim text-xs font-black uppercase cursor-pointer">Cancel</button>
                <button 
                  onClick={() => { onAddContact(newContact); setNewContact({name:'', address:''}); setShowAdd(false); }} 
                  className="flex-[2] py-3 bg-xmr-green text-xmr-base text-xs font-black uppercase cursor-pointer"
                >
                  Save_Contact
                </button>
              </div>
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
