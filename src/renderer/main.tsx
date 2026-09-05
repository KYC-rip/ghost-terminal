import './polyfills';
// Self-hosted DM Sans (the --font-display face). Bundled via @fontsource so the woff2
// files ship inside the app and load same-origin ('self') — no request to Google's CDN
// (an IP leak that bypassed Tor/proxiedGet) and no CSP allowance for external font hosts.
// Weights mirror the old Google Fonts request: 400/500/700/800 + 400 italic.
import '@fontsource/dm-sans/400.css';
import '@fontsource/dm-sans/400-italic.css';
import '@fontsource/dm-sans/500.css';
import '@fontsource/dm-sans/700.css';
import '@fontsource/dm-sans/800.css';
import { installTauriBridge } from './tauriBridge';
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// If running under Tauri, install the compatibility bridge
// that maps window.api.* → Tauri invoke() calls
installTauriBridge();

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
