import { describe, it, expect } from 'vitest';
import { getWalletDirName, getRpcFolderName, getNetworkFlag, getNetworkLabel, parseCapabilities } from '../networkPaths';

describe('getWalletDirName', () => {
  it('hard-separates stressnet wallets; mainnet/stagenet keep the legacy dir', () => {
    expect(getWalletDirName('mainnet')).toBe('wallets');
    expect(getWalletDirName('stagenet')).toBe('wallets');
    expect(getWalletDirName('stressnet')).toBe('wallets-stressnet');
  });
});

describe('getRpcFolderName', () => {
  it('selects the stressnet binary only for stressnet', () => {
    expect(getRpcFolderName('mainnet')).toBe('rpc-core');
    expect(getRpcFolderName('stagenet')).toBe('rpc-core');
    expect(getRpcFolderName('stressnet')).toBe('rpc-stressnet');
  });
});

describe('getNetworkFlag', () => {
  it('maps networks to wallet-rpc CLI flags (stressnet is a testnet fork)', () => {
    expect(getNetworkFlag('mainnet')).toBeNull();
    expect(getNetworkFlag('stagenet')).toBe('--stagenet');
    expect(getNetworkFlag('testnet')).toBe('--testnet');
    expect(getNetworkFlag('stressnet')).toBe('--testnet');
  });
});

describe('getNetworkLabel', () => {
  it('drives the header chip', () => {
    expect(getNetworkLabel('mainnet')).toBe('');
    expect(getNetworkLabel('stagenet')).toBe('STAGENET');
    expect(getNetworkLabel('stressnet')).toBe('FCMP++ STRESSNET');
  });
});

describe('parseCapabilities', () => {
  it('fails safe: missing/corrupt manifests hide stressnet', () => {
    expect(parseCapabilities(null)).toEqual({ stressnet: false });
    expect(parseCapabilities(undefined)).toEqual({ stressnet: false });
    expect(parseCapabilities('not json{')).toEqual({ stressnet: false });
    expect(parseCapabilities('{}')).toEqual({ stressnet: false });
    expect(parseCapabilities('{"stressnet":"yes"}')).toEqual({ stressnet: false });
  });

  it('enables stressnet only on an explicit true', () => {
    expect(parseCapabilities('{"stressnet":true}')).toEqual({ stressnet: true });
  });
});
