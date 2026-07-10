/**
 * Process-wide network mode mirror for the renderer. App.tsx sets this from
 * engine status; leaf consumers (fiat hook, dispatch tabs, faucet card) read
 * it without threading props through every layer. The value only changes
 * with a full engine reload, so render-time staleness is not a concern.
 */

let currentLabel = '';

export function setNetworkLabel(label: string) {
  currentLabel = label || '';
}

export function getActiveNetworkLabel(): string {
  return currentLabel;
}

export function isStressnet(): boolean {
  return currentLabel.includes('STRESSNET');
}
