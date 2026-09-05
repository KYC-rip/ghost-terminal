// src/renderer/services/subaddressService.ts
// Shared "get-or-create" subaddress logic.
// Reuses an existing zero-balance subaddress with the given prefix,
// or creates a new one only when all previous ones have received funds.

export interface SubaddressEntry {
  index: number;
  address: string;
  label: string;
  balance?: string;
  unlockedBalance?: string;
  isUsed?: boolean;
}

/**
 * Find an unused subaddress with the given label prefix, or create a new one.
 *
 * @param prefix    Label prefix to search/create with (e.g. "Swap", "Ghost", "Payment")
 * @param list      Current subaddress list from VaultContext
 * @param createFn  VaultContext.createSubaddress — receives the full label, returns address string
 * @returns         The subaddress string, or null if creation failed
 */
export async function getOrCreateSubaddress(
  prefix: string,
  list: SubaddressEntry[],
  createFn: (label?: string) => Promise<string | null | undefined>,
): Promise<string | null> {
  // Look for an existing subaddress with this prefix that has zero balance
  const unused = list.find(
    (s) =>
      s.label.startsWith(`${prefix}_`) &&
      parseFloat(s.balance || '0') === 0 &&
      parseFloat(s.unlockedBalance || '0') === 0,
  );

  if (unused) return unused.address;

  // All prefixed subaddresses have been used — create a fresh one
  const label = `${prefix}_${new Date().toISOString().replace('T', '_').slice(0, 19)}`;
  return createFn(label).then(addr => addr ?? null);
}
