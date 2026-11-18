// NetWatch service worker: shows push notifications and opens NetWatch when one is tapped.
// It doesn't cache any network data.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { title: "NetWatch", body: e.data ? e.data.text() : "" }; }
  const title = String(d.title || "NetWatch").slice(0, 120);
  e.waitUntil(self.registration.showNotification(title, {
    body: String(d.body || "").slice(0, 900),
    tag: d.tag || undefined,
    renotify: !!d.tag,
    requireInteraction: d.severity === "escalation",
    icon: "/icons/icon-192.png",
    badge: "/icons/badge-96.png",
    data: { url: typeof d.url === "string" && d.url.startsWith("/") ? d.url : "/" },
  }));
});

self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL(e.notification.data && e.notification.data.url || "/", self.location.origin);
  if (url.origin !== self.location.origin) return;            // only ever open NetWatch itself
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    for (const c of list) {
      if (new URL(c.url).origin === url.origin && "focus" in c) return c.focus();
    }
    return self.clients.openWindow(url.href);
  }));
});
