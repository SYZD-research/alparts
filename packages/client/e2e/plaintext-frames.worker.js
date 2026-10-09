// Control for the SFU call check: passes every frame unchanged and ignores
// keys, as a client without frame encryption would. Loaded only by the test
// page with ?control=plaintext-frames.
self.onmessage = () => undefined;
self.addEventListener('rtctransform', (event) => {
  const { readable, writable } = event.transformer;
  readable.pipeTo(writable).catch(() => undefined);
});
