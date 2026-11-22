// LYV room: decrypts the mood board's files for readers who hold the room key. It has no secrets of its own:
// the key comes from the signed-in room tab (sessionStorage) and is asked for again on every page load, so a
// locked room can no longer open the board.
const TYPES = { html: "text/html; charset=utf-8", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp", avif: "image/avif", svg: "image/svg+xml", gif: "image/gif" };
let aes = null, mac = null, asking = null;
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
async function setKey(b64) {
  if (!b64) { aes = mac = null; return; }
  const raw = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
  aes = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  mac = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}
self.addEventListener("message", (e) => {
  if (e.data && e.data.type === "mb-key") setKey(e.data.key).then(() => e.ports[0] && e.ports[0].postMessage("ok"));
});
function ask() {
  if (!asking) asking = (async () => {
    const cs = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of cs) {
      const k = await new Promise((res) => { const ch = new MessageChannel(), t = setTimeout(() => res(null), 1500); ch.port1.onmessage = (ev) => { clearTimeout(t); res(ev.data); }; try { c.postMessage({ type: "mb-key-request" }, [ch.port2]); } catch (err) { res(null); } });
      if (k) { await setKey(k); return true; }
    }
    await setKey(null); return false;
  })().finally(() => { asking = null; });
  return asking;
}
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
self.addEventListener("fetch", (e) => {
  const scope = self.registration.scope, url = e.request.url.split("#")[0].split("?")[0];
  if (!url.startsWith(scope) || e.request.method !== "GET") return;
  e.respondWith((async () => {
    if (e.request.mode === "navigate" || !aes) await ask();
    if (!aes) return new Response("Open the mood board from the LYV room.", { status: 403, headers: { "content-type": "text/plain; charset=utf-8" } });
    const rel = decodeURIComponent(url.slice(scope.length)) || "index.html";
    const name = hex(await crypto.subtle.sign("HMAC", mac, new TextEncoder().encode("lyv-mb:" + rel))).slice(0, 32);
    const r = await fetch(new URL("../mb-data/" + name + ".bin", scope), { cache: "no-cache" }); // revalidate: a republished file keeps its name
    if (!r.ok) return new Response("Not found", { status: 404 });
    const u = new Uint8Array(await r.arrayBuffer());
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(0, 12) }, aes, u.slice(12));
      return new Response(plain, { headers: { "content-type": TYPES[(rel.split(".").pop() || "").toLowerCase()] || "application/octet-stream", "cache-control": "no-store" } });
    } catch (err) { return new Response("Could not open", { status: 403 }); }
  })());
});
