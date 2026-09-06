// Standard Polyfills
(window as any).global = window;
if (!(window as any).process) {
  (window as any).process = { env: { NODE_DEBUG: false }, versions: { electron: '1.0.0' }, nextTick: (cb: any) => setTimeout(cb, 0) };
}

// 🔥 Tactical FS Mock for monero-ts
// This matches the Node.js fs.promises API structure expected by the library
const mockFsPromises = {
  readFile: async () => { throw new Error("MOCK_FS_DISABLED"); },
  writeFile: async () => { },
  mkdir: async () => { },
  unlink: async () => { },
  stat: async () => { throw new Error("MOCK_FS_DISABLED"); },
  access: async () => { },
  rename: async () => { },
  copyFile: async () => { },
  readdir: async () => []
};

const mockFs = {
  promises: mockFsPromises
};

(window as any).fs = mockFs;
(globalThis as any).fs = mockFs;

