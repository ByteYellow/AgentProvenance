'use strict';
// Evidence shards contain only base64-encoded bytes. The fixed wrapper below
// never interprets evidence as JavaScript or inserts it into an HTML document.
window.AgentProvOffline = (() => {
  const root = new URL(document.querySelector('meta[name="agentprov-site-root"]').content, location.href);
  const pending = new Map();
  const catalog = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(atob(window.AgentProvOfflineCatalog), c=>c.charCodeAt(0))));
  delete window.AgentProvOfflineCatalog;
  function accept(path, encoded) {
    const request = pending.get(path);
    if (!request || request.bytes) throw new Error('Unexpected offline replay shard');
    if (typeof encoded !== 'string' || encoded.length > request.limit || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new Error('Invalid offline replay shard');
    request.bytes = Uint8Array.from(atob(encoded), c=>c.charCodeAt(0));
  }
  function read(ref) {
    if (!/^data\/[a-f0-9]{64}\.json\.gz$/.test(ref.path) || !Number.isSafeInteger(ref.bytes) || ref.bytes < 0 || ref.bytes > 64 * 1024 * 1024) return Promise.reject(new Error('Invalid offline replay reference'));
    if (pending.has(ref.path)) return pending.get(ref.path).promise;
    const request = {limit:4*Math.ceil((ref.bytes+65536)/3),bytes:null};
    const script = document.createElement('script');
    pending.set(ref.path,request);
    request.promise = new Promise((resolve,reject)=>{
      script.onload = () => request.bytes ? resolve(request.bytes) : reject(new Error('Offline replay shard contains no data'));
      script.onerror = () => reject(new Error('Offline replay data could not be loaded'));
      script.src = new URL(ref.path.replace(/\.json\.gz$/,'.js'),root).href;
      document.head.appendChild(script);
    }).finally(()=>{pending.delete(ref.path);script.remove();});
    return request.promise;
  }
  const initial = new URL(location.href);
  initial.searchParams.set('live','0');
  if (!initial.searchParams.get('run')) initial.searchParams.set('run',catalog.summaries[0].run);
  history.replaceState(null,'',initial);
  return Object.freeze({read,accept,manifest:()=>structuredClone(catalog)});
})();
