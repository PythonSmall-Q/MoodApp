export const Output = {
  Debug: (...args: any[]) => console.log('[DEBUG]', ...args),
  Log: (...args: any[]) => console.log('[LOG]', ...args),
  Warn: (...args: any[]) => console.warn('[WARN]', ...args),
  Error: (...args: any[]) => console.error('[ERROR]', ...args),
};
