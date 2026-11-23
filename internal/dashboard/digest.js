// Keep the check on LAN HTTP and offline, where Web Crypto can be absent.
window.agentProvSHA256 = async bytes => {
  if (!globalThis.crypto?.subtle) return window.sha256(bytes);
  const data = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  return Array.from(data, n => n.toString(16).padStart(2, '0')).join('');
};
